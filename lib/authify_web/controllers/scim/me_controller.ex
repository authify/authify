defmodule AuthifyWeb.SCIM.MeController do
  @moduledoc """
  SCIM 2.0 /Me endpoint per RFC 7644 Section 3.11.

  Provides authenticated access for users to manage their own SCIM resource
  without needing to know their user ID. This is particularly useful for:
  - Self-service profile management
  - OAuth-authenticated applications with limited scope
  - Personal Access Tokens

  The /Me endpoint is an alias for /Users/:id where :id is the authenticated user.
  """

  use AuthifyWeb.SCIM.BaseController

  alias Authify.Accounts
  alias Authify.SCIM.ResourceFormatter
  alias AuthifyWeb.SCIM.{Helpers, Mappers, PatchOperations}

  @doc """
  GET /scim/v2/Me

  Returns the authenticated user's SCIM resource.
  Requires `scim:me` or broader read scope.
  Supports attributes and excludedAttributes query parameters.
  """
  def show(conn, params) do
    case ensure_scim_scope(conn, "scim:me") do
      {:ok, _conn} ->
        user = get_authenticated_user(conn)

        if user do
          # Preload emails and groups for SCIM response
          user = Authify.Repo.preload(user, [:emails, :groups])
          base_url = Helpers.build_base_url(conn)

          resource =
            user
            |> ResourceFormatter.format_user(base_url)
            |> Helpers.filter_attributes(params)

          render_scim_resource(conn, resource, resource_struct: user)
        else
          render_scim_error(conn, 401, :sensitive, "Authentication required")
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end

  @doc """
  PUT /scim/v2/Me

  Replaces the authenticated user's resource (full update).
  Requires `scim:me:write` or broader write scope.
  """
  def update(conn, params) do
    case ensure_scim_scope(conn, "scim:me:write") do
      {:ok, _conn} ->
        user = get_authenticated_user(conn)

        if user do
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
        else
          render_scim_error(conn, 401, :sensitive, "Authentication required")
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end

  @doc """
  PATCH /scim/v2/Me

  Partially updates the authenticated user using SCIM PATCH operations.
  Requires `scim:me:write` or broader write scope.
  """
  def patch(conn, params) do
    case ensure_scim_scope(conn, "scim:me:write") do
      {:ok, _conn} ->
        user = get_authenticated_user(conn)

        if user do
          # Parse PATCH operations
          operations = params["Operations"] || []

          case PatchOperations.apply_user_patch_operations(user, operations) do
            {:ok, updated_user} ->
              updated_user = Authify.Repo.preload(updated_user, :groups)
              base_url = Helpers.build_base_url(conn)
              resource = ResourceFormatter.format_user(updated_user, base_url)
              render_scim_resource(conn, resource, resource_struct: updated_user)

            {:error, reason} ->
              render_scim_error(conn, 400, :invalid_value, reason)
          end
        else
          render_scim_error(conn, 401, :sensitive, "Authentication required")
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end

  # Private functions

  defp get_authenticated_user(conn) do
    # The user is set by APIAuth plug in conn.assigns
    conn.assigns[:current_user]
  end
end
