defmodule AuthifyWeb.SCIM.UsersController do
  @moduledoc """
  SCIM 2.0 Users resource endpoint per RFC 7644 Section 3.

  Provides CRUD operations for user provisioning from external systems.
  """

  use AuthifyWeb.SCIM.BaseController

  alias Authify.Accounts
  alias Authify.SCIM.ResourceFormatter
  alias AuthifyWeb.Helpers.AuditHelper
  alias AuthifyWeb.SCIM.{Helpers, Mappers, PatchOperations}

  @doc """
  GET /scim/v2/Users

  Lists users with optional filtering, sorting, and pagination.
  """
  def index(conn, params) do
    organization = conn.assigns[:current_organization]

    # Check scope
    case ensure_scim_scope(conn, "scim:users:read") do
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

        # Fetch users and count
        case Accounts.list_users_scim(organization.id, opts) do
          {:ok, users} ->
            case Accounts.count_users_scim(organization.id, filter: params["filter"]) do
              {:ok, total} ->
                base_url = Helpers.build_base_url(conn)

                resources =
                  Enum.map(users, fn user ->
                    user
                    |> ResourceFormatter.format_user(base_url)
                    |> Helpers.filter_attributes(params)
                  end)

                render_scim_list(conn, resources, total, start_index, count, :user)

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
  GET /scim/v2/Users/:id

  Returns a single user by ID.
  Supports attributes and excludedAttributes query parameters.
  """
  def show(conn, %{"id" => id} = params) do
    organization = conn.assigns[:current_organization]

    case ensure_scim_scope(conn, "scim:users:read") do
      {:ok, _conn} ->
        case Accounts.get_user(id) do
          nil ->
            render_scim_error(conn, 404, :no_target, "User not found")

          user ->
            # Verify user belongs to organization (multi-tenant isolation)
            case Helpers.validate_resource_organization(user, organization) do
              :ok ->
                # Preload emails and groups for SCIM response
                user = Authify.Repo.preload(user, [:emails, :groups])
                base_url = Helpers.build_base_url(conn)

                resource =
                  user
                  |> ResourceFormatter.format_user(base_url)
                  |> Helpers.filter_attributes(params)

                render_scim_resource(conn, resource, resource_struct: user)

              {:error, :not_found} ->
                render_scim_error(conn, 404, :no_target, "User not found")
            end
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end

  @doc """
  POST /scim/v2/Users

  Creates a new user from SCIM data.
  """
  def create(conn, params) do
    organization = conn.assigns[:current_organization]

    case ensure_scim_scope(conn, "scim:users:write") do
      {:ok, _conn} ->
        # Map SCIM attributes to Authify user attributes
        attrs = Mappers.map_user_attrs(params)

        # Create user via SCIM-specific function
        case Accounts.create_user_scim(attrs, organization.id) do
          {:ok, user} ->
            AuditHelper.log_event_async(
              conn,
              :scim_user_provisioned,
              "user",
              user.id,
              "success",
              %{
                "user_id" => user.id,
                "username" => user.username,
                "external_id" => user.external_id,
                "organization_slug" => organization.slug
              }
            )

            render_created_user(conn, user)

          {:error, %Ecto.Changeset{} = changeset} ->
            handle_create_error(conn, changeset, attrs)

          {:error, reason} ->
            render_scim_error(conn, 400, :invalid_value, "Failed to create user: #{reason}")
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end

  defp render_created_user(conn, user) do
    user = Authify.Repo.preload(user, :groups)
    base_url = Helpers.build_base_url(conn)
    resource = ResourceFormatter.format_user(user, base_url)

    conn
    |> put_resp_header("location", "#{base_url}/Users/#{user.id}")
    |> render_scim_resource(resource, status: 201, resource_struct: user)
  end

  defp handle_create_error(conn, changeset, attrs) do
    errors = Ecto.Changeset.traverse_errors(changeset, & &1)

    cond do
      Map.has_key?(errors, :external_id) ->
        render_scim_error(
          conn,
          409,
          :uniqueness,
          "User with externalId '#{attrs[:external_id]}' already exists"
        )

      has_email_uniqueness_error?(changeset) ->
        email_value = get_duplicate_email_value(changeset)

        render_scim_error(
          conn,
          409,
          :uniqueness,
          "User with email '#{email_value}' already exists"
        )

      Map.has_key?(errors, :username) ->
        render_scim_error(
          conn,
          409,
          :uniqueness,
          "User with userName '#{attrs[:username]}' already exists"
        )

      true ->
        detail = Helpers.format_changeset_errors(changeset)
        render_scim_error(conn, 400, :invalid_value, detail)
    end
  end

  @doc """
  PUT /scim/v2/Users/:id

  Replaces an existing user (full update).
  """
  def update(conn, %{"id" => id} = params) do
    organization = conn.assigns[:current_organization]

    case ensure_scim_scope(conn, "scim:users:write") do
      {:ok, _conn} ->
        case Accounts.get_user(id) do
          nil ->
            render_scim_error(conn, 404, :no_target, "User not found")

          user ->
            do_update_user(conn, user, organization, params)
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end

  @doc """
  PATCH /scim/v2/Users/:id

  Partially updates a user using SCIM PATCH operations.
  """
  def patch(conn, %{"id" => id} = params) do
    organization = conn.assigns[:current_organization]

    case ensure_scim_scope(conn, "scim:users:write") do
      {:ok, _conn} ->
        case Accounts.get_user(id) do
          nil ->
            render_scim_error(conn, 404, :no_target, "User not found")

          user ->
            case Helpers.validate_resource_organization(user, organization) do
              :ok ->
                # Parse PATCH operations
                operations = params["Operations"] || []

                case PatchOperations.apply_user_patch_operations(user, operations) do
                  {:ok, updated_user} ->
                    AuditHelper.log_event_async(
                      conn,
                      :scim_user_updated,
                      "user",
                      updated_user.id,
                      "success",
                      %{
                        "user_id" => updated_user.id,
                        "username" => updated_user.username,
                        "external_id" => updated_user.external_id,
                        "organization_slug" => organization.slug,
                        "operation" => "patch",
                        "operations_count" => length(operations)
                      }
                    )

                    updated_user = Authify.Repo.preload(updated_user, :groups)
                    base_url = Helpers.build_base_url(conn)
                    resource = ResourceFormatter.format_user(updated_user, base_url)
                    render_scim_resource(conn, resource, resource_struct: updated_user)

                  {:error, reason} ->
                    render_scim_error(conn, 400, :invalid_value, reason)
                end

              {:error, :not_found} ->
                render_scim_error(conn, 404, :no_target, "User not found")
            end
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end

  # Private helper for update to reduce nesting
  defp do_update_user(conn, user, organization, params) do
    case Helpers.validate_resource_organization(user, organization) do
      :ok ->
        # Map SCIM attributes to Authify user attributes
        attrs = Mappers.map_user_attrs(params)

        # Validate immutable fields
        case Helpers.validate_immutable_field(
               attrs,
               :external_id,
               user.external_id,
               "externalId"
             ) do
          :ok ->
            case Accounts.update_user_scim(user, attrs) do
              {:ok, updated_user} ->
                AuditHelper.log_event_async(
                  conn,
                  :scim_user_updated,
                  "user",
                  updated_user.id,
                  "success",
                  %{
                    "user_id" => updated_user.id,
                    "username" => updated_user.username,
                    "external_id" => updated_user.external_id,
                    "organization_slug" => organization.slug,
                    "operation" => "update"
                  }
                )

                updated_user = Authify.Repo.preload(updated_user, :groups)
                base_url = Helpers.build_base_url(conn)
                resource = ResourceFormatter.format_user(updated_user, base_url)
                render_scim_resource(conn, resource, resource_struct: updated_user)

              {:error, %Ecto.Changeset{} = changeset} ->
                detail = Helpers.format_changeset_errors(changeset)
                render_scim_error(conn, 400, :invalid_value, detail)

              {:error, reason} ->
                render_scim_error(conn, 400, :invalid_value, "Failed to update user: #{reason}")
            end

          {:error, message} ->
            render_scim_error(conn, 400, :mutability, message)
        end

      {:error, :not_found} ->
        render_scim_error(conn, 404, :no_target, "User not found")
    end
  end

  @doc """
  DELETE /scim/v2/Users/:id

  Soft deletes a user (sets active=false).
  """
  def delete(conn, %{"id" => id}) do
    organization = conn.assigns[:current_organization]

    case ensure_scim_scope(conn, "scim:users:write") do
      {:ok, _conn} ->
        case Accounts.get_user(id) do
          nil ->
            render_scim_error(conn, 404, :no_target, "User not found")

          user ->
            case Helpers.validate_resource_organization(user, organization) do
              :ok ->
                case Accounts.update_user_scim(user, %{active: false}) do
                  {:ok, deleted_user} ->
                    AuditHelper.log_event_async(
                      conn,
                      :scim_user_deleted,
                      "user",
                      deleted_user.id,
                      "success",
                      %{
                        "user_id" => deleted_user.id,
                        "username" => deleted_user.username,
                        "external_id" => deleted_user.external_id,
                        "organization_slug" => organization.slug
                      }
                    )

                    send_resp(conn, 204, "")

                  {:error, reason} ->
                    render_scim_error(
                      conn,
                      400,
                      :invalid_value,
                      "Failed to delete user: #{reason}"
                    )
                end

              {:error, :not_found} ->
                render_scim_error(conn, 404, :no_target, "User not found")
            end
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end

  # Private functions

  # Check if changeset has a uniqueness error on any email
  defp has_email_uniqueness_error?(changeset) do
    case Ecto.Changeset.get_change(changeset, :emails) do
      nil ->
        false

      email_changesets when is_list(email_changesets) ->
        Enum.any?(email_changesets, fn
          %Ecto.Changeset{errors: errors} ->
            Enum.any?(errors, fn
              {:value, {_msg, [constraint: :unique, constraint_name: _]}} -> true
              _ -> false
            end)

          _ ->
            false
        end)

      _ ->
        false
    end
  end

  # Get the email value that caused the uniqueness error
  defp get_duplicate_email_value(changeset) do
    case Ecto.Changeset.get_change(changeset, :emails) do
      nil ->
        "unknown"

      email_changesets when is_list(email_changesets) ->
        email_changeset =
          Enum.find(email_changesets, fn
            %Ecto.Changeset{errors: errors} ->
              Enum.any?(errors, fn
                {:value, {_msg, [constraint: :unique, constraint_name: _]}} -> true
                _ -> false
              end)

            _ ->
              false
          end)

        case email_changeset do
          %Ecto.Changeset{} ->
            Ecto.Changeset.get_field(email_changeset, :value, "unknown")

          _ ->
            "unknown"
        end

      _ ->
        "unknown"
    end
  end
end
