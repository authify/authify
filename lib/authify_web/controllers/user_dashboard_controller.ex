defmodule AuthifyWeb.UserDashboardController do
  use AuthifyWeb, :controller

  alias Authify.Accounts
  alias Authify.Accounts.User
  alias Authify.OAuth

  def index(conn, _params) do
    user = conn.assigns.current_user |> Authify.Repo.preload(:emails)
    organization = conn.assigns.current_organization

    # Get applications accessible to this user
    accessible_apps = Accounts.get_user_accessible_applications(user, organization)

    # Get user's grants for showing authorization status
    user_grants = OAuth.list_user_grants(user)
    grant_map = Map.new(user_grants, fn grant -> {grant.application_id, grant} end)

    conn
    |> assign(:current_page, "user_dashboard")
    |> render(:index,
      user: user,
      user_email: User.get_primary_email_value(user),
      organization: organization,
      oauth2_applications: accessible_apps.oauth2_applications,
      saml_service_providers: accessible_apps.saml_service_providers,
      user_grants: grant_map
    )
  end
end
