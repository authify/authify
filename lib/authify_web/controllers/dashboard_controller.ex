defmodule AuthifyWeb.DashboardController do
  use AuthifyWeb, :controller

  alias Authify.Accounts

  def index(conn, _params) do
    user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    if organization.slug == "authify-global" do
      # Global admin dashboard - show system-wide data
      system_stats = Accounts.get_system_stats()
      invitation_stats = Accounts.get_invitation_stats()

      render(conn, :index,
        user: user,
        organization: organization,
        users: system_stats.recent_users,
        user_count: system_stats.total_users,
        is_global_dashboard: true,
        system_stats: system_stats,
        invitation_stats: invitation_stats
      )
    else
      # Regular organization dashboard
      users = Accounts.list_users(organization.id)

      render(conn, :index,
        user: user,
        organization: organization,
        users: users,
        user_count: length(users),
        is_global_dashboard: false
      )
    end
  end
end
