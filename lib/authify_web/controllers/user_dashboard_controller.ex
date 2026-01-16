defmodule AuthifyWeb.UserDashboardController do
  use AuthifyWeb, :controller

  alias Authify.Accounts
  alias Authify.Accounts.User

  def index(conn, _params) do
    user = conn.assigns.current_user |> Authify.Repo.preload(:emails)
    organization = conn.assigns.current_organization

    # Get applications accessible to this user
    accessible_apps = Accounts.get_user_accessible_applications(user, organization)

    conn
    |> assign(:current_page, "user_dashboard")
    |> render(:index,
      user: user,
      user_email: User.get_primary_email_value(user),
      organization: organization,
      oauth2_applications: accessible_apps.oauth2_applications,
      saml_service_providers: accessible_apps.saml_service_providers
    )
  end
end
