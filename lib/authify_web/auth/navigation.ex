defmodule AuthifyWeb.Auth.Navigation do
  @moduledoc """
  Provides shared post-authentication navigation logic.
  """

  use Phoenix.VerifiedRoutes,
    endpoint: AuthifyWeb.Endpoint,
    router: AuthifyWeb.Router

  alias Authify.Accounts.User

  @doc """
  Returns the dashboard path for a user within an organization.

  Admins are directed to the admin dashboard; all other users are directed
  to the user dashboard.
  """
  def dashboard_path_for_user(user, organization) do
    if User.admin?(user, organization.id) or User.global_admin?(user) do
      ~p"/#{organization.slug}/dashboard"
    else
      ~p"/#{organization.slug}/user/dashboard"
    end
  end
end