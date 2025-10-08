defmodule AuthifyWeb.PageController do
  use AuthifyWeb, :controller

  alias Authify.Accounts

  def home(conn, _params) do
    case conn.assigns[:current_user] do
      nil ->
        # User not authenticated, check if any users exist
        if users_exist?() do
          # Users exist, redirect to login
          redirect(conn, to: ~p"/login")
        else
          # No users exist, redirect to initial setup
          redirect(conn, to: ~p"/setup")
        end

      user ->
        # User is authenticated, redirect based on organization and role
        # Get user's current organization from session or default
        org_id = get_session(conn, :current_organization_id)

        organization =
          if org_id do
            Accounts.get_organization(org_id)
          else
            # Get user's organization
            user.organization
          end

        cond do
          # No organization found - safety fallback
          is_nil(organization) ->
            redirect(conn, to: ~p"/login")

          # Global org admin - go to global admin dashboard
          organization.slug == "authify-global" && Accounts.User.admin?(user, organization.id) ->
            redirect(conn, to: ~p"/authify-global/dashboard")

          # Global org non-admin user - this shouldn't normally happen
          # Redirect them to their user dashboard as a safe fallback
          organization.slug == "authify-global" ->
            redirect(conn, to: ~p"/authify-global/user/dashboard")

          # Tenant org admin - go to org admin dashboard
          Accounts.User.admin?(user, organization.id) ->
            redirect(conn, to: ~p"/#{organization.slug}/dashboard")

          # Tenant org regular user - go to user dashboard
          true ->
            redirect(conn, to: ~p"/#{organization.slug}/user/dashboard")
        end
    end
  end

  defp users_exist? do
    Accounts.count_users() > 0
  end
end
