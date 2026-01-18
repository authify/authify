defmodule AuthifyWeb.SCIM.GroupsController do
  @moduledoc """
  SCIM 2.0 Groups resource endpoint per RFC 7644 Section 3.

  Provides CRUD operations for group provisioning from external systems.
  """

  use AuthifyWeb.SCIM.BaseController

  alias Authify.Accounts
  alias Authify.SCIM.ResourceFormatter

  @doc """
  GET /scim/v2/Groups

  Lists groups with optional filtering, sorting, and pagination.
  """
  def index(conn, params) do
    organization = conn.assigns[:current_organization]

    # Check scope
    case ensure_scim_scope(conn, "scim:groups:read") do
      {:ok, _conn} ->
        # Parse pagination params (SCIM uses 1-based indexing)
        start_index = parse_int(params["startIndex"], 1)
        count = min(parse_int(params["count"], 25), 100)
        page = div(start_index - 1, count) + 1

        # Build query options
        opts = [
          page: page,
          per_page: count,
          filter: params["filter"],
          sort_by: params["sortBy"],
          sort_order: params["sortOrder"]
        ]

        # Fetch groups and count
        case Accounts.list_groups_scim(organization.id, opts) do
          {:ok, groups} ->
            case Accounts.count_groups_scim(organization.id, filter: params["filter"]) do
              {:ok, total} ->
                base_url = build_base_url(conn)

                resources =
                  Enum.map(groups, fn group ->
                    ResourceFormatter.format_group(group, organization.id, base_url)
                  end)

                render_scim_list(conn, resources, total, start_index, count, :group)

              {:error, reason} ->
                render_scim_error(conn, 400, :invalid_filter, "Invalid filter: #{reason}")
            end

          {:error, reason} ->
            render_scim_error(conn, 400, :invalid_filter, "Invalid filter: #{reason}")
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end

  @doc """
  GET /scim/v2/Groups/:id

  Returns a single group by ID.
  """
  def show(conn, %{"id" => id}) do
    organization = conn.assigns[:current_organization]

    case ensure_scim_scope(conn, "scim:groups:read") do
      {:ok, _conn} ->
        case Accounts.get_group(id) do
          nil ->
            render_scim_error(conn, 404, :no_target, "Group not found")

          group ->
            # Verify group belongs to organization (multi-tenant isolation)
            if group.organization_id == organization.id do
              # Preload users for SCIM response
              group = Authify.Repo.preload(group, :users)
              base_url = build_base_url(conn)
              resource = ResourceFormatter.format_group(group, organization.id, base_url)
              render_scim_resource(conn, resource)
            else
              render_scim_error(conn, 404, :no_target, "Group not found")
            end
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end

  @doc """
  POST /scim/v2/Groups

  Creates a new group from SCIM data.
  """
  def create(conn, params) do
    organization = conn.assigns[:current_organization]

    case ensure_scim_scope(conn, "scim:groups:write") do
      {:ok, _conn} ->
        # Map SCIM attributes to Authify group attributes
        attrs = map_scim_to_group_attrs(params)

        # Create group via SCIM-specific function
        case Accounts.create_group_scim(attrs, organization.id) do
          {:ok, group} ->
            render_created_group(conn, group, organization.id)

          {:error, %Ecto.Changeset{} = changeset} ->
            handle_create_error(conn, changeset, attrs)

          {:error, reason} ->
            render_scim_error(conn, 400, :invalid_value, "Failed to create group: #{reason}")
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end

  defp render_created_group(conn, group, organization_id) do
    group = Authify.Repo.preload(group, :users)
    base_url = build_base_url(conn)
    resource = ResourceFormatter.format_group(group, organization_id, base_url)

    conn
    |> put_resp_header("location", "#{base_url}/Groups/#{group.id}")
    |> render_scim_resource(resource, status: 201)
  end

  defp handle_create_error(conn, changeset, attrs) do
    cond do
      has_uniqueness_error?(changeset, :external_id) ->
        render_scim_error(
          conn,
          409,
          :uniqueness,
          "Group with externalId '#{attrs[:external_id]}' already exists"
        )

      has_uniqueness_error?(changeset, :name) ->
        render_scim_error(
          conn,
          409,
          :uniqueness,
          "Group with displayName '#{attrs[:name]}' already exists"
        )

      true ->
        detail = format_changeset_errors(changeset)
        render_scim_error(conn, 400, :invalid_value, detail)
    end
  end

  # Check if changeset has a uniqueness constraint error on a specific field
  defp has_uniqueness_error?(changeset, field) do
    Enum.any?(changeset.errors, fn
      {^field, {_msg, opts}} -> Keyword.get(opts, :constraint) == :unique
      _ -> false
    end)
  end

  @doc """
  PUT /scim/v2/Groups/:id

  Replaces an existing group (full update).
  """
  def update(conn, %{"id" => id} = params) do
    organization = conn.assigns[:current_organization]

    case ensure_scim_scope(conn, "scim:groups:write") do
      {:ok, _conn} ->
        case Accounts.get_group(id) do
          nil ->
            render_scim_error(conn, 404, :no_target, "Group not found")

          group ->
            do_update_group(conn, group, organization, params)
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end

  @doc """
  PATCH /scim/v2/Groups/:id

  Partially updates a group using SCIM PATCH operations.
  """
  def patch(conn, %{"id" => id} = params) do
    organization = conn.assigns[:current_organization]

    case ensure_scim_scope(conn, "scim:groups:write") do
      {:ok, _conn} ->
        case Accounts.get_group(id) do
          nil ->
            render_scim_error(conn, 404, :no_target, "Group not found")

          group ->
            if group.organization_id == organization.id do
              # Parse PATCH operations
              operations = params["Operations"] || []

              case apply_patch_operations(group, operations, organization) do
                {:ok, updated_group} ->
                  updated_group = Authify.Repo.preload(updated_group, :users)
                  base_url = build_base_url(conn)

                  resource =
                    ResourceFormatter.format_group(updated_group, organization.id, base_url)

                  render_scim_resource(conn, resource)

                {:error, reason} ->
                  render_scim_error(conn, 400, :invalid_value, reason)
              end
            else
              render_scim_error(conn, 404, :no_target, "Group not found")
            end
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end

  # Private helper for update to reduce nesting
  defp do_update_group(conn, group, organization, params) do
    if group.organization_id == organization.id do
      # Map SCIM attributes to Authify group attributes
      attrs = map_scim_to_group_attrs(params)

      # Validate immutable fields
      if attrs[:external_id] && attrs[:external_id] != group.external_id do
        render_scim_error(
          conn,
          400,
          :mutability,
          "Attribute 'externalId' is immutable and cannot be modified"
        )
      else
        case Accounts.update_group_scim(group, attrs) do
          {:ok, updated_group} ->
            updated_group = Authify.Repo.preload(updated_group, :users)
            base_url = build_base_url(conn)
            resource = ResourceFormatter.format_group(updated_group, organization.id, base_url)
            render_scim_resource(conn, resource)

          {:error, %Ecto.Changeset{} = changeset} ->
            detail = format_changeset_errors(changeset)
            render_scim_error(conn, 400, :invalid_value, detail)

          {:error, reason} ->
            render_scim_error(conn, 400, :invalid_value, "Failed to update group: #{reason}")
        end
      end
    else
      render_scim_error(conn, 404, :no_target, "Group not found")
    end
  end

  @doc """
  DELETE /scim/v2/Groups/:id

  Deletes a group.
  """
  def delete(conn, %{"id" => id}) do
    organization = conn.assigns[:current_organization]

    case ensure_scim_scope(conn, "scim:groups:write") do
      {:ok, _conn} ->
        case Accounts.get_group(id) do
          nil ->
            render_scim_error(conn, 404, :no_target, "Group not found")

          group ->
            if group.organization_id == organization.id do
              case Accounts.delete_group(group) do
                {:ok, _group} ->
                  send_resp(conn, 204, "")

                {:error, reason} ->
                  render_scim_error(
                    conn,
                    400,
                    :invalid_value,
                    "Failed to delete group: #{inspect(reason)}"
                  )
              end
            else
              render_scim_error(conn, 404, :no_target, "Group not found")
            end
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end

  # Private functions

  defp build_base_url(conn) do
    org_slug = conn.assigns[:current_organization].slug
    "#{AuthifyWeb.Endpoint.url()}/#{org_slug}/scim/v2"
  end

  defp parse_int(nil, default), do: default

  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_int(value, _default) when is_integer(value), do: value

  # Maps SCIM group attributes to Authify group attributes
  defp map_scim_to_group_attrs(params) do
    %{}
    |> map_display_name(params)
    |> map_external_id(params)
  end

  defp map_display_name(attrs, params) do
    if params["displayName"],
      do: Map.put(attrs, :name, params["displayName"]),
      else: attrs
  end

  defp map_external_id(attrs, params) do
    if params["externalId"],
      do: Map.put(attrs, :external_id, params["externalId"]),
      else: attrs
  end

  # Applies SCIM PATCH operations to a group
  defp apply_patch_operations(group, operations, organization) do
    Enum.reduce_while(operations, {:ok, group}, fn op, {:ok, current_group} ->
      case apply_single_patch_op(current_group, op, organization) do
        {:ok, updated_group} -> {:cont, {:ok, updated_group}}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  defp apply_single_patch_op(
         group,
         %{"op" => "replace", "path" => path, "value" => value},
         _organization
       ) do
    case normalize_path(path) do
      "displayname" ->
        Accounts.update_group_scim(group, %{name: value})

      _ ->
        {:error, "Unsupported PATCH path: #{path}"}
    end
  end

  defp apply_single_patch_op(group, %{"op" => "replace", "value" => value}, _organization)
       when is_map(value) do
    # Replace operation with no path - update entire resource
    attrs = map_scim_to_group_attrs(value)
    Accounts.update_group_scim(group, attrs)
  end

  defp apply_single_patch_op(
         group,
         %{"op" => "add", "path" => "members", "value" => members},
         organization
       )
       when is_list(members) do
    # Add members to the group
    case add_members_to_group(group, members, organization) do
      :ok -> {:ok, Authify.Repo.preload(group, :users, force: true)}
      {:error, reason} -> {:error, reason}
    end
  end

  defp apply_single_patch_op(group, %{"op" => "remove", "path" => path}, organization) do
    # Remove members from the group
    # Path format: members[value eq "user-id"]
    case parse_member_filter(path) do
      {:ok, user_id} ->
        case remove_member_from_group(group, user_id, organization) do
          :ok -> {:ok, Authify.Repo.preload(group, :users, force: true)}
          {:error, reason} -> {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp apply_single_patch_op(_group, op, _organization) do
    {:error, "Unsupported PATCH operation: #{op["op"]} with path #{op["path"]}"}
  end

  defp normalize_path(nil), do: nil
  defp normalize_path(path) when is_binary(path), do: String.downcase(path)

  # Add multiple members to a group
  defp add_members_to_group(group, members, organization) do
    Enum.reduce_while(members, :ok, fn member, :ok ->
      user_id = member["value"]

      case Accounts.get_user(user_id) do
        nil ->
          {:halt, {:error, "User with id '#{user_id}' not found"}}

        user ->
          if user.organization_id == organization.id do
            case Accounts.add_user_to_group(user, group) do
              {:ok, _} -> {:cont, :ok}
              # Already a member, ignore
              {:error, %Ecto.Changeset{}} -> {:cont, :ok}
              {:error, reason} -> {:halt, {:error, "Failed to add member: #{inspect(reason)}"}}
            end
          else
            {:halt, {:error, "User '#{user_id}' does not belong to this organization"}}
          end
      end
    end)
  end

  # Remove a member from a group
  defp remove_member_from_group(group, user_id, organization) do
    case Accounts.get_user(user_id) do
      nil ->
        {:error, "User with id '#{user_id}' not found"}

      user ->
        if user.organization_id == organization.id do
          Accounts.remove_user_from_group(user, group)
          :ok
        else
          {:error, "User '#{user_id}' does not belong to this organization"}
        end
    end
  end

  # Parse member filter from path like: members[value eq "123"]
  defp parse_member_filter(path) do
    case Regex.run(~r/members\[value eq "(.+?)"\]/i, path) do
      [_, user_id] -> {:ok, user_id}
      _ -> {:error, "Invalid member filter path: #{path}"}
    end
  end

  defp format_changeset_errors(changeset) do
    errors =
      Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
        Enum.reduce(opts, msg, fn {key, value}, acc ->
          String.replace(acc, "%{#{key}}", to_string(value))
        end)
      end)

    Enum.map_join(errors, "; ", fn {field, messages} ->
      formatted_messages = format_error_messages(messages)
      "#{field}: #{formatted_messages}"
    end)
  end

  # Format error messages, handling both simple strings and nested errors from associations
  defp format_error_messages(messages) when is_list(messages) do
    messages
    |> Enum.map_join(", ", &format_error_message/1)
  end

  defp format_error_messages(message), do: format_error_message(message)

  defp format_error_message(msg) when is_binary(msg), do: msg

  defp format_error_message(msg) when is_map(msg) do
    # Nested error from association
    Enum.map_join(msg, "; ", fn {field, messages} ->
      "#{field}: #{format_error_messages(messages)}"
    end)
  end

  defp format_error_message(msg), do: inspect(msg)
end
