defmodule Authify.SCIMClient.Client do
  @moduledoc """
  Context for managing SCIM client configurations and provisioning operations.
  """

  import Ecto.Query, warn: false
  alias Authify.Repo

  alias Authify.SCIMClient.{ExternalId, ScimClient, SyncLog}

  @doc """
  Returns the list of SCIM clients for an organization.
  """
  def list_scim_clients(organization_id) do
    ScimClient
    |> where([c], c.organization_id == ^organization_id)
    |> order_by([c], desc: c.inserted_at)
    |> Repo.all()
  end

  @doc """
  Returns the list of active SCIM clients for an organization filtered by resource type.
  """
  def list_active_scim_clients(organization_id, :user) do
    ScimClient
    |> where(
      [c],
      c.organization_id == ^organization_id and c.is_active == true and c.sync_users == true
    )
    |> Repo.all()
  end

  def list_active_scim_clients(organization_id, :group) do
    ScimClient
    |> where(
      [c],
      c.organization_id == ^organization_id and c.is_active == true and c.sync_groups == true
    )
    |> Repo.all()
  end

  @doc """
  Returns a paginated list of SCIM clients for an organization.
  """
  def list_scim_clients(organization_id, opts) do
    page = opts[:page] || 1
    per_page = opts[:per_page] || 25
    offset = (page - 1) * per_page

    clients =
      ScimClient
      |> where([c], c.organization_id == ^organization_id)
      |> order_by([c], desc: c.inserted_at)
      |> limit(^per_page)
      |> offset(^offset)
      |> Repo.all()

    total =
      ScimClient
      |> where([c], c.organization_id == ^organization_id)
      |> Repo.aggregate(:count, :id)

    {clients, total}
  end

  @doc """
  Gets a single SCIM client.
  Raises `Ecto.NoResultsError` if the client does not exist.
  """
  def get_scim_client!(id, organization_id) do
    ScimClient
    |> where([c], c.id == ^id and c.organization_id == ^organization_id)
    |> Repo.one!()
  end

  @doc """
  Gets a single SCIM client, returns nil if not found.
  """
  def get_scim_client(id, organization_id) do
    ScimClient
    |> where([c], c.id == ^id and c.organization_id == ^organization_id)
    |> Repo.one()
  end

  @doc """
  Creates a SCIM client.
  """
  def create_scim_client(attrs, organization_id) do
    # Ensure we have string keys
    attrs =
      attrs
      |> Enum.map(fn {k, v} -> {to_string(k), v} end)
      |> Enum.into(%{})
      |> Map.put("organization_id", organization_id)

    %ScimClient{}
    |> ScimClient.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a SCIM client.
  """
  def update_scim_client(%ScimClient{} = scim_client, attrs) do
    scim_client
    |> ScimClient.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a SCIM client.
  """
  def delete_scim_client(%ScimClient{} = scim_client) do
    Repo.delete(scim_client)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking SCIM client changes.
  """
  def change_scim_client(%ScimClient{} = scim_client, attrs \\ %{}) do
    ScimClient.changeset(scim_client, attrs)
  end

  ## Sync Logs

  @doc """
  Creates a sync log.
  """
  def create_sync_log(attrs) do
    %SyncLog{}
    |> SyncLog.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a sync log to success status.
  """
  def update_sync_log_success(sync_log, http_status, response_body, external_id \\ nil) do
    attrs = %{
      status: "success",
      http_status: http_status,
      response_body: Jason.encode!(response_body)
    }

    result =
      sync_log
      |> SyncLog.update_changeset(attrs)
      |> Repo.update()

    # Store external ID if provided
    if external_id do
      store_external_id(
        sync_log.scim_client_id,
        sync_log.resource_type,
        sync_log.resource_id,
        external_id
      )
    end

    result
  end

  @doc """
  Updates a sync log to failed status.
  """
  def update_sync_log_failure(sync_log, reason, next_retry_at) do
    error_message =
      case reason do
        {:http_error, status, body} ->
          "HTTP #{status}: #{inspect(body)}"

        {:network_error, error} ->
          "Network error: #{inspect(error)}"

        {:error, msg} when is_binary(msg) ->
          msg

        other ->
          inspect(other)
      end

    attrs = %{
      status: "failed",
      error_message: error_message,
      retry_count: sync_log.retry_count + 1,
      next_retry_at: next_retry_at
    }

    sync_log
    |> SyncLog.update_changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Updates a sync log when max retries reached.
  """
  def update_sync_log_max_retries(sync_log) do
    attrs = %{
      status: "failed",
      error_message: "Max retries reached (#{sync_log.retry_count})",
      next_retry_at: nil
    }

    sync_log
    |> SyncLog.update_changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Gets sync logs that are ready for retry.
  """
  def get_retriable_sync_logs do
    now = DateTime.utc_now()

    SyncLog
    |> where([l], l.status == "failed" and not is_nil(l.next_retry_at))
    |> where([l], l.next_retry_at <= ^now)
    |> Repo.all()
    |> Repo.preload(:scim_client)
  end

  @doc """
  Gets sync logs for a SCIM client.
  """
  def list_sync_logs(scim_client_id, opts \\ []) do
    page = opts[:page] || 1
    per_page = opts[:per_page] || 50
    offset = (page - 1) * per_page

    logs =
      SyncLog
      |> where([l], l.scim_client_id == ^scim_client_id)
      |> order_by([l], desc: l.inserted_at)
      |> limit(^per_page)
      |> offset(^offset)
      |> Repo.all()

    total =
      SyncLog
      |> where([l], l.scim_client_id == ^scim_client_id)
      |> Repo.aggregate(:count, :id)

    {logs, total}
  end

  ## External IDs

  @doc """
  Stores an external ID for a resource.
  """
  def store_external_id(scim_client_id, resource_type, resource_id, external_id) do
    resource_type_str = to_string(resource_type) |> String.capitalize()

    # Try to find existing record
    case ExternalId
         |> where(
           [e],
           e.scim_client_id == ^scim_client_id and e.resource_type == ^resource_type_str and
             e.resource_id == ^resource_id
         )
         |> Repo.one() do
      nil ->
        # Insert new record
        attrs = %{
          scim_client_id: scim_client_id,
          resource_type: resource_type_str,
          resource_id: resource_id,
          external_id: external_id
        }

        %ExternalId{}
        |> ExternalId.changeset(attrs)
        |> Repo.insert()

      existing ->
        # Update existing record
        existing
        |> ExternalId.changeset(%{external_id: external_id})
        |> Repo.update()
    end
  end

  @doc """
  Gets the external ID for a resource.
  """
  def get_external_id(scim_client_id, resource_type, resource_id) do
    resource_type_str = to_string(resource_type) |> String.capitalize()

    case ExternalId
         |> where(
           [e],
           e.scim_client_id == ^scim_client_id and e.resource_type == ^resource_type_str and
             e.resource_id == ^resource_id
         )
         |> Repo.one() do
      nil -> {:error, :not_found}
      %ExternalId{external_id: external_id} -> {:ok, external_id}
    end
  end

  @doc """
  Deletes external ID mappings for a resource across all SCIM clients.
  """
  def delete_external_ids(resource_type, resource_id) do
    resource_type_str = to_string(resource_type) |> String.capitalize()

    ExternalId
    |> where([e], e.resource_type == ^resource_type_str and e.resource_id == ^resource_id)
    |> Repo.delete_all()
  end
end
