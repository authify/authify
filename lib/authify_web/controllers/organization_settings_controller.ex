defmodule AuthifyWeb.OrganizationSettingsController do
  use AuthifyWeb, :controller

  alias Authify.OAuth

  def show(conn, _params) do
    user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    # Get management API application count
    management_api_count = OAuth.list_management_api_applications(organization) |> length()

    render(conn, :show,
      user: user,
      organization: organization,
      management_api_count: management_api_count,
      page_title: "Organization Settings"
    )
  end

  def management_api(conn, _params) do
    user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    # Get management API applications for this organization
    management_applications = OAuth.list_management_api_applications(organization)

    render(conn, :management_api,
      user: user,
      organization: organization,
      management_applications: management_applications,
      page_title: "Management API Access"
    )
  end

  def new_management_api_app(conn, _params) do
    user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    render(conn, :new_management_api,
      user: user,
      organization: organization,
      page_title: "Create Management API Application"
    )
  end

  def create_management_api_app(conn, %{"application" => app_params, "scopes" => scopes}) do
    organization = conn.assigns.current_organization

    # Ensure scopes is a list (remove empty strings from checkbox values)
    scopes_list =
      case scopes do
        nil -> []
        [] -> []
        scopes when is_list(scopes) -> Enum.reject(scopes, &(&1 == ""))
        scopes when is_binary(scopes) -> String.split(scopes, " ") |> Enum.reject(&(&1 == ""))
      end

    # Create management API application
    app_params =
      app_params
      |> Map.put("organization_id", organization.id)
      |> Map.put("application_type", "management_api_app")
      |> Map.put("scopes", scopes_list)
      # Management API apps don't need redirect URIs
      |> Map.put("redirect_uris", "")
      |> Map.put("is_active", true)

    case OAuth.create_application(app_params) do
      {:ok, _application} ->
        conn
        |> put_flash(:info, "Management API application created successfully.")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/settings/management-api")

      {:error, _changeset} ->
        # For now, just redirect with error - could enhance with proper error handling
        conn
        |> put_flash(:error, "Failed to create Management API application. Please try again.")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/settings/management-api")
    end
  end

  def create_management_api_app(conn, %{"application" => app_params}) do
    # Handle case where no scopes are selected - pass empty scopes array
    create_management_api_app(conn, %{"application" => app_params, "scopes" => []})
  end

  def update_management_api_app(conn, %{
        "id" => id,
        "application" => app_params,
        "scopes" => scopes
      }) do
    organization = conn.assigns.current_organization

    # Ensure scopes is a list (remove empty strings from checkbox values)
    scopes_list =
      case scopes do
        nil -> []
        [] -> []
        scopes when is_list(scopes) -> Enum.reject(scopes, &(&1 == ""))
        scopes when is_binary(scopes) -> String.split(scopes, " ") |> Enum.reject(&(&1 == ""))
      end

    app_params = Map.put(app_params, "scopes", scopes_list)

    try do
      application = OAuth.get_management_api_application!(id, organization)

      case OAuth.update_application(application, app_params) do
        {:ok, _application} ->
          conn
          |> put_flash(:info, "Management API application updated successfully")
          |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/settings/management-api")

        {:error, %Ecto.Changeset{}} ->
          conn
          |> put_flash(:error, "Error updating application")
          |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/settings/management-api")
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_flash(:error, "Application not found")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/settings/management-api")
    end
  end

  def update_management_api_app(conn, %{"id" => id, "application" => app_params}) do
    # Handle case where no scopes are selected
    update_management_api_app(conn, %{"id" => id, "application" => app_params, "scopes" => []})
  end

  def delete_management_api_app(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization

    try do
      application = OAuth.get_management_api_application!(id, organization)

      case OAuth.delete_application(application) do
        {:ok, _application} ->
          conn
          |> put_flash(:info, "Management API application deleted successfully")
          |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/settings/management-api")

        {:error, _changeset} ->
          conn
          |> put_flash(:error, "Error deleting application")
          |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/settings/management-api")
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_flash(:error, "Application not found")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/settings/management-api")
    end
  end
end
