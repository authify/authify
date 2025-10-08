defmodule AuthifyWeb.API.ApplicationsController do
  use AuthifyWeb.API.BaseController

  alias Authify.OAuth

  # Helper to check if user has permission for an application type
  defp can_access_application_type?(scopes, application_type, :read) do
    case application_type do
      "management_api_app" -> "management_app:read" in scopes or "management_app:write" in scopes
      "oauth2_app" -> "applications:read" in scopes or "applications:write" in scopes
      _ -> false
    end
  end

  defp can_access_application_type?(scopes, application_type, :write) do
    case application_type do
      "management_api_app" -> "management_app:write" in scopes
      "oauth2_app" -> "applications:write" in scopes
      _ -> false
    end
  end

  @doc """
  GET /{org_slug}/api/applications

  Returns a paginated list of OAuth applications for the organization.
  Requires applications:read for oauth2_app types and/or management_app:read for management_api_app types.
  """
  def index(conn, params) do
    scopes = conn.assigns[:current_scopes] || []
    organization = conn.assigns.current_organization

    # Check if user has at least one valid scope
    has_oauth_read = "applications:read" in scopes or "applications:write" in scopes
    has_mgmt_read = "management_app:read" in scopes or "management_app:write" in scopes

    if has_oauth_read or has_mgmt_read do
      page = String.to_integer(params["page"] || "1")
      per_page = String.to_integer(params["per_page"] || "25")

      # Determine which application types the user can see
      allowed_types =
        []
        |> then(fn types -> if has_oauth_read, do: ["oauth2_app" | types], else: types end)
        |> then(fn types -> if has_mgmt_read, do: ["management_api_app" | types], else: types end)

      # Fetch applications filtered by allowed types
      {applications, total} =
        OAuth.list_all_applications(organization, allowed_types, page: page, per_page: per_page)

      page_info = %{
        page: page,
        per_page: per_page,
        total: total
      }

      render_collection_response(conn, applications,
        resource_type: "application",
        page_info: page_info,
        exclude: [:client_secret]
      )
    else
      render_error_response(
        conn,
        :forbidden,
        "insufficient_scope",
        "Requires applications:read or management_app:read scope"
      )
    end
  end

  @doc """
  GET /{org_slug}/api/applications/:id

  Get a specific OAuth application by ID.
  Requires applications:read for oauth2_app or management_app:read for management_api_app.
  """
  def show(conn, %{"id" => id}) do
    scopes = conn.assigns[:current_scopes] || []
    organization = conn.assigns.current_organization

    try do
      application = OAuth.get_application!(id, organization)

      if can_access_application_type?(scopes, application.application_type, :read) do
        render_api_response(conn, application,
          resource_type: "application",
          exclude: [:client_secret]
        )
      else
        render_error_response(
          conn,
          :forbidden,
          "insufficient_scope",
          "Requires #{scope_for_type(application.application_type, :read)} scope"
        )
      end
    rescue
      Ecto.NoResultsError ->
        render_error_response(
          conn,
          :not_found,
          "resource_not_found",
          "Application not found in organization"
        )
    end
  end

  defp scope_for_type("management_api_app", :read), do: "management_app:read"
  defp scope_for_type("management_api_app", :write), do: "management_app:write"
  defp scope_for_type("oauth2_app", :read), do: "applications:read"
  defp scope_for_type("oauth2_app", :write), do: "applications:write"
  defp scope_for_type(_, _), do: "unknown"

  @doc """
  POST /{org_slug}/api/applications

  Create a new OAuth application in the current organization.
  Requires applications:write for oauth2_app or management_app:write for management_api_app.
  """
  def create(conn, %{"application" => application_params}) do
    scopes = conn.assigns[:current_scopes] || []
    organization = conn.assigns.current_organization

    # Determine the application type from params (default to oauth2_app)
    app_type = application_params["application_type"] || "oauth2_app"

    if can_access_application_type?(scopes, app_type, :write) do
      attrs = Map.put(application_params, "organization_id", organization.id)

      case OAuth.create_application(attrs) do
        {:ok, application} ->
          # Include client_secret in creation response only
          application_with_secret =
            application
            |> Map.from_struct()
            |> Map.put(:client_secret_display, application.client_secret)
            |> Map.put(:__struct__, Authify.OAuth.Application)

          render_api_response(conn, application_with_secret,
            resource_type: "application",
            status: :created
          )

        {:error, changeset} ->
          render_validation_errors(conn, changeset)
      end
    else
      render_error_response(
        conn,
        :forbidden,
        "insufficient_scope",
        "Requires #{scope_for_type(app_type, :write)} scope"
      )
    end
  end

  @doc """
  PUT /{org_slug}/api/applications/:id

  Update an OAuth application's configuration.
  Requires applications:write for oauth2_app or management_app:write for management_api_app.
  """
  def update(conn, %{"id" => id, "application" => application_params}) do
    scopes = conn.assigns[:current_scopes] || []
    organization = conn.assigns.current_organization

    try do
      application = OAuth.get_application!(id, organization)

      if can_access_application_type?(scopes, application.application_type, :write) do
        case OAuth.update_application(application, application_params) do
          {:ok, updated_application} ->
            render_api_response(conn, updated_application,
              resource_type: "application",
              exclude: [:client_secret]
            )

          {:error, changeset} ->
            render_validation_errors(conn, changeset)
        end
      else
        render_error_response(
          conn,
          :forbidden,
          "insufficient_scope",
          "Requires #{scope_for_type(application.application_type, :write)} scope"
        )
      end
    rescue
      Ecto.NoResultsError ->
        render_error_response(
          conn,
          :not_found,
          "resource_not_found",
          "Application not found in organization"
        )
    end
  end

  @doc """
  DELETE /{org_slug}/api/applications/:id

  Delete an OAuth application from the organization.
  Requires applications:write for oauth2_app or management_app:write for management_api_app.
  """
  def delete(conn, %{"id" => id}) do
    scopes = conn.assigns[:current_scopes] || []
    organization = conn.assigns.current_organization

    try do
      application = OAuth.get_application!(id, organization)

      if can_access_application_type?(scopes, application.application_type, :write) do
        case OAuth.delete_application(application) do
          {:ok, _application} ->
            send_resp(conn, :no_content, "")

          {:error, changeset} ->
            render_validation_errors(conn, changeset)
        end
      else
        render_error_response(
          conn,
          :forbidden,
          "insufficient_scope",
          "Requires #{scope_for_type(application.application_type, :write)} scope"
        )
      end
    rescue
      Ecto.NoResultsError ->
        render_error_response(
          conn,
          :not_found,
          "resource_not_found",
          "Application not found in organization"
        )
    end
  end

  @doc """
  POST /{org_slug}/api/applications/:id/regenerate-secret

  Generate a new client secret for the OAuth application.
  Requires applications:write for oauth2_app or management_app:write for management_api_app.
  """
  def regenerate_secret(conn, %{"application_id" => id}) do
    scopes = conn.assigns[:current_scopes] || []
    organization = conn.assigns.current_organization

    try do
      application = OAuth.get_application!(id, organization)

      if can_access_application_type?(scopes, application.application_type, :write) do
        # Generate new client secret
        new_secret = :crypto.strong_rand_bytes(32) |> Base.hex_encode32(case: :lower)

        case OAuth.update_application(application, %{"client_secret" => new_secret}) do
          {:ok, updated_application} ->
            # Return the new secret in response (only time it's shown)
            application_with_secret =
              updated_application
              |> Map.from_struct()
              |> Map.put(:client_secret_display, new_secret)
              |> Map.put(:__struct__, Authify.OAuth.Application)

            render_api_response(conn, application_with_secret, resource_type: "application")

          {:error, changeset} ->
            render_validation_errors(conn, changeset)
        end
      else
        render_error_response(
          conn,
          :forbidden,
          "insufficient_scope",
          "Requires #{scope_for_type(application.application_type, :write)} scope"
        )
      end
    rescue
      Ecto.NoResultsError ->
        render_error_response(
          conn,
          :not_found,
          "resource_not_found",
          "Application not found in organization"
        )
    end
  end
end
