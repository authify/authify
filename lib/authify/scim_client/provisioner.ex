defmodule Authify.SCIMClient.Provisioner do
  @moduledoc """
  Core provisioning logic for SCIM client operations.
  Handles create/update/delete operations for users and groups.
  """

  require Logger

  alias Authify.Accounts
  alias Authify.Accounts.{Group, Organization, User}
  alias Authify.SCIMClient.{AttributeMapper, Client, DefaultMappings, HTTPClient}

  @max_retries 5

  @doc """
  Performs a full sync of all users and groups to a specific SCIM client.

  This manually triggers provisioning of all resources, useful for:
  - Initial setup of a new SCIM client
  - Recovering from sync failures
  - Reconciling state between Authify and the remote system
  """
  def full_sync(client) do
    require Logger

    Logger.info("Starting full sync for SCIM client #{client.id} (#{client.name})")

    # Sync users if enabled
    users_synced =
      if client.sync_users do
        users = Accounts.list_users(client.organization_id)
        Logger.info("Syncing #{length(users)} users to SCIM client #{client.id}")

        Enum.each(users, fn user ->
          # Preload emails for user mapping
          user = Authify.Repo.preload(user, :emails)

          # Try to determine if this user already exists in the remote system
          case Client.get_external_id(client.id, :user, user.id) do
            {:ok, _external_id} ->
              # User exists, update it
              provision_to_client(:updated, :user, user, client)

            _ ->
              # User doesn't exist, create it
              provision_to_client(:created, :user, user, client)
          end
        end)

        length(users)
      else
        0
      end

    # Sync groups if enabled
    groups_synced =
      if client.sync_groups do
        organization = Authify.Repo.get!(Organization, client.organization_id)
        groups = Accounts.list_groups(organization)
        Logger.info("Syncing #{length(groups)} groups to SCIM client #{client.id}")

        Enum.each(groups, fn group ->
          # Try to determine if this group already exists in the remote system
          case Client.get_external_id(client.id, :group, group.id) do
            {:ok, _external_id} ->
              # Group exists, update it
              provision_to_client(:updated, :group, group, client)

            _ ->
              # Group doesn't exist, create it
              provision_to_client(:created, :group, group, client)
          end
        end)

        length(groups)
      else
        0
      end

    Logger.info(
      "Full sync completed for SCIM client #{client.id}: #{users_synced} users, #{groups_synced} groups"
    )

    {:ok, %{users_synced: users_synced, groups_synced: groups_synced}}
  end

  @doc """
  Provisions a resource change to all active SCIM clients for the organization.

  Checks if SCIM outbound provisioning is enabled for the organization before proceeding.
  """
  def provision(event, resource_type, resource) when event in [:created, :updated, :deleted] do
    # Check if SCIM outbound provisioning is enabled for this organization
    organization = Authify.Repo.get!(Organization, resource.organization_id)

    enabled =
      Authify.Configurations.get_organization_setting(
        organization,
        :scim_outbound_provisioning_enabled
      )

    if enabled do
      # Get all active SCIM clients for this organization
      clients = Client.list_active_scim_clients(resource.organization_id, resource_type)

      Enum.each(clients, fn client ->
        provision_to_client(event, resource_type, resource, client)
      end)
    else
      Logger.debug(
        "SCIM outbound provisioning disabled for organization #{organization.id}, skipping provisioning"
      )
    end
  end

  @doc """
  Provisions a single resource change to a specific SCIM client.
  """
  def provision_to_client(event, resource_type, resource, client) do
    start_time = System.monotonic_time()

    # DURABILITY: Write to database FIRST (survives restarts)
    {:ok, log} =
      Client.create_sync_log(%{
        scim_client_id: client.id,
        resource_type: resource_type_to_string(resource_type),
        resource_id: resource.id,
        operation: event_to_string(event),
        status: "pending"
      })

    # REAL-TIME: Process immediately via async task
    result = perform_operation(event, resource_type, resource, client)

    duration = System.monotonic_time() - start_time

    case result do
      {:ok, response_body, http_status} ->
        external_id = extract_external_id(response_body)
        Client.update_sync_log_success(log, http_status, response_body, external_id)

        # Emit success telemetry
        :telemetry.execute(
          [:authify, :scim_client, :provision],
          %{duration: duration},
          %{
            result: :success,
            event: event,
            resource_type: resource_type,
            scim_client_id: client.id,
            http_status: http_status
          }
        )

      {:error, reason} ->
        next_retry = calculate_next_retry(0)
        Client.update_sync_log_failure(log, reason, next_retry)

        # Emit failure telemetry
        :telemetry.execute(
          [:authify, :scim_client, :provision],
          %{duration: duration},
          %{
            result: :error,
            event: event,
            resource_type: resource_type,
            scim_client_id: client.id,
            error: format_error(reason)
          }
        )

        Logger.warning(
          "SCIM provisioning failed for #{resource_type} #{resource.id} to client #{client.id}: #{format_error(reason)}"
        )

        # RetryScheduler will pick this up later
    end
  end

  @doc """
  Retries a failed sync operation.
  """
  def retry_sync(log) do
    if log.retry_count >= @max_retries do
      Client.update_sync_log_max_retries(log)
    else
      # Reload the SCIM client
      client = log.scim_client

      # Determine resource type and operation
      resource_type = string_to_resource_type(log.resource_type)
      event = string_to_event(log.operation)

      # Load the resource (user or group)
      resource = load_resource(resource_type, log.resource_id, client.organization_id)

      case resource do
        nil ->
          # Resource was deleted, mark sync as failed
          Client.update_sync_log_failure(
            log,
            {:error, "Resource no longer exists"},
            nil
          )

        resource ->
          # Retry the operation
          result = perform_operation(event, resource_type, resource, client)

          case result do
            {:ok, response_body, http_status} ->
              external_id = extract_external_id(response_body)
              Client.update_sync_log_success(log, http_status, response_body, external_id)

            {:error, reason} ->
              next_retry = calculate_next_retry(log.retry_count)
              Client.update_sync_log_failure(log, reason, next_retry)
          end
      end
    end
  end

  # Private functions

  defp perform_operation(:created, :user, %User{} = user, client) do
    mapping = get_user_mapping(client)
    payload = AttributeMapper.map_user(user, mapping)
    HTTPClient.create_user(client, payload)
  end

  defp perform_operation(:updated, :user, %User{} = user, client) do
    case Client.get_external_id(client.id, :user, user.id) do
      {:ok, external_id} ->
        mapping = get_user_mapping(client)
        payload = AttributeMapper.map_user(user, mapping)
        HTTPClient.update_user(client, external_id, payload)

      _ ->
        {:error, :no_external_id}
    end
  end

  defp perform_operation(:deleted, :user, %User{} = user, client) do
    case Client.get_external_id(client.id, :user, user.id) do
      {:ok, external_id} ->
        HTTPClient.delete_user(client, external_id)

      _ ->
        {:error, :no_external_id}
    end
  end

  defp perform_operation(:created, :group, %Group{} = group, client) do
    mapping = get_group_mapping(client)
    payload = AttributeMapper.map_group(group, mapping)
    HTTPClient.create_group(client, payload)
  end

  defp perform_operation(:updated, :group, %Group{} = group, client) do
    case Client.get_external_id(client.id, :group, group.id) do
      {:ok, external_id} ->
        mapping = get_group_mapping(client)
        payload = AttributeMapper.map_group(group, mapping)
        HTTPClient.update_group(client, external_id, payload)

      _ ->
        {:error, :no_external_id}
    end
  end

  defp perform_operation(:deleted, :group, %Group{} = group, client) do
    case Client.get_external_id(client.id, :group, group.id) do
      {:ok, external_id} ->
        HTTPClient.delete_group(client, external_id)

      _ ->
        {:error, :no_external_id}
    end
  end

  defp get_user_mapping(client) do
    case decode_mapping(client.attribute_mapping) do
      {:ok, mapping} -> Map.get(mapping, "user", DefaultMappings.generic_mapping()["user"])
      _ -> DefaultMappings.generic_mapping()["user"]
    end
  end

  defp get_group_mapping(client) do
    case decode_mapping(client.attribute_mapping) do
      {:ok, mapping} -> Map.get(mapping, "group", DefaultMappings.generic_mapping()["group"])
      _ -> DefaultMappings.generic_mapping()["group"]
    end
  end

  defp decode_mapping(nil), do: {:error, :no_mapping}
  defp decode_mapping(""), do: {:error, :no_mapping}

  defp decode_mapping(mapping_json) when is_binary(mapping_json) do
    case Jason.decode(mapping_json) do
      {:ok, mapping} -> {:ok, mapping}
      {:error, _} -> {:error, :invalid_json}
    end
  end

  defp calculate_next_retry(retry_count) when retry_count < @max_retries do
    # Exponential backoff: 5min, 15min, 45min, 2h, 6h
    delay_seconds = :math.pow(3, retry_count) * 300
    DateTime.add(DateTime.utc_now(), trunc(delay_seconds), :second)
  end

  defp calculate_next_retry(_retry_count), do: nil

  defp extract_external_id(response_body) when is_map(response_body) do
    Map.get(response_body, "id")
  end

  defp extract_external_id(_), do: nil

  defp resource_type_to_string(:user), do: "User"
  defp resource_type_to_string(:group), do: "Group"
  defp resource_type_to_string(type) when is_binary(type), do: type

  defp string_to_resource_type("User"), do: :user
  defp string_to_resource_type("Group"), do: :group

  defp event_to_string(:created), do: "create"
  defp event_to_string(:updated), do: "update"
  defp event_to_string(:deleted), do: "delete"

  defp string_to_event("create"), do: :created
  defp string_to_event("update"), do: :updated
  defp string_to_event("delete"), do: :deleted

  defp load_resource(:user, resource_id, organization_id) do
    Authify.Repo.get_by(User, id: resource_id, organization_id: organization_id)
    |> Authify.Repo.preload(:emails)
  end

  defp load_resource(:group, resource_id, organization_id) do
    Authify.Repo.get_by(Group, id: resource_id, organization_id: organization_id)
  end

  # Format error for logging and telemetry
  defp format_error({:http_error, status, body}) when is_map(body) do
    detail = Map.get(body, "detail", inspect(body))
    "HTTP #{status}: #{detail}"
  end

  defp format_error({:http_error, status, body}) do
    "HTTP #{status}: #{inspect(body)}"
  end

  defp format_error({:network_error, reason}) do
    "Network error: #{inspect(reason)}"
  end

  defp format_error(:no_external_id) do
    "No external ID found for resource"
  end
end
