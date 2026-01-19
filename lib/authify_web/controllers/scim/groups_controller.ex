defmodule AuthifyWeb.SCIM.GroupsController do
  @moduledoc """
  SCIM 2.0 Groups resource endpoint per RFC 7644 Section 3.

  Provides CRUD operations for group provisioning from external systems.
  """

  use AuthifyWeb.SCIM.BaseController

  alias Authify.Accounts
  alias Authify.SCIM.ResourceFormatter
  alias AuthifyWeb.SCIM.{Helpers, Mappers, PatchOperations}

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
        {start_index, count, page} = Helpers.parse_pagination_params(params)

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
                base_url = Helpers.build_base_url(conn)

                resources =
                  Enum.map(groups, fn group ->
                    group
                    |> ResourceFormatter.format_group(organization.id, base_url)
                    |> Helpers.filter_attributes(params)
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
  Supports attributes and excludedAttributes query parameters.
  """
  def show(conn, %{"id" => id} = params) do
    organization = conn.assigns[:current_organization]

    case ensure_scim_scope(conn, "scim:groups:read") do
      {:ok, _conn} ->
        case Accounts.get_group(id) do
          nil ->
            render_scim_error(conn, 404, :no_target, "Group not found")

          group ->
            # Verify group belongs to organization (multi-tenant isolation)
            case Helpers.validate_resource_organization(group, organization) do
              :ok ->
                # Preload users for SCIM response
                group = Authify.Repo.preload(group, :users)
                base_url = Helpers.build_base_url(conn)

                resource =
                  group
                  |> ResourceFormatter.format_group(organization.id, base_url)
                  |> Helpers.filter_attributes(params)

                render_scim_resource(conn, resource, resource_struct: group)

              {:error, :not_found} ->
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
        attrs = Mappers.map_group_attrs(params)

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
    base_url = Helpers.build_base_url(conn)
    resource = ResourceFormatter.format_group(group, organization_id, base_url)

    conn
    |> put_resp_header("location", "#{base_url}/Groups/#{group.id}")
    |> render_scim_resource(resource, status: 201, resource_struct: group)
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
        detail = Helpers.format_changeset_errors(changeset)
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
            case Helpers.validate_resource_organization(group, organization) do
              :ok ->
                # Parse PATCH operations
                operations = params["Operations"] || []

                case PatchOperations.apply_group_patch_operations(group, operations, organization) do
                  {:ok, updated_group} ->
                    updated_group = Authify.Repo.preload(updated_group, :users)
                    base_url = Helpers.build_base_url(conn)

                    resource =
                      ResourceFormatter.format_group(updated_group, organization.id, base_url)

                    render_scim_resource(conn, resource, resource_struct: updated_group)

                  {:error, reason} ->
                    render_scim_error(conn, 400, :invalid_value, reason)
                end

              {:error, :not_found} ->
                render_scim_error(conn, 404, :no_target, "Group not found")
            end
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end

  # Private helper for update to reduce nesting
  defp do_update_group(conn, group, organization, params) do
    case Helpers.validate_resource_organization(group, organization) do
      :ok ->
        # Map SCIM attributes to Authify group attributes
        attrs = Mappers.map_group_attrs(params)

        # Validate immutable fields
        case Helpers.validate_immutable_field(
               attrs,
               :external_id,
               group.external_id,
               "externalId"
             ) do
          :ok ->
            case Accounts.update_group_scim(group, attrs) do
              {:ok, updated_group} ->
                updated_group = Authify.Repo.preload(updated_group, :users)
                base_url = Helpers.build_base_url(conn)

                resource =
                  ResourceFormatter.format_group(updated_group, organization.id, base_url)

                render_scim_resource(conn, resource, resource_struct: updated_group)

              {:error, %Ecto.Changeset{} = changeset} ->
                detail = Helpers.format_changeset_errors(changeset)
                render_scim_error(conn, 400, :invalid_value, detail)

              {:error, reason} ->
                render_scim_error(conn, 400, :invalid_value, "Failed to update group: #{reason}")
            end

          {:error, message} ->
            render_scim_error(conn, 400, :mutability, message)
        end

      {:error, :not_found} ->
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
            case Helpers.validate_resource_organization(group, organization) do
              :ok ->
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

              {:error, :not_found} ->
                render_scim_error(conn, 404, :no_target, "Group not found")
            end
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end
end
