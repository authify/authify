defmodule AuthifyWeb.Auth.OrganizationContext do
  @moduledoc """
  Plug to ensure users can only access their own organization's data.
  Adds the current user's organization to the connection assigns.
  """

  import Plug.Conn
  import Phoenix.Controller

  alias Authify.Accounts
  alias Authify.Guardian

  def init(opts), do: opts

  def call(conn, opts) do
    conn = setup_organization_context(conn)

    # Apply additional checks based on options
    case opts do
      :require_admin -> require_admin(conn)
      :require_super_admin -> require_super_admin(conn)
      _ -> conn
    end
  end

  defp setup_organization_context(conn) do
    case Guardian.Plug.current_resource(conn) do
      nil ->
        # User not authenticated - let the auth pipeline handle this
        conn

      user ->
        # Load user with organization relationship
        user_with_org = Accounts.get_user_with_organizations!(user.id)
        {conn, organization} = get_current_organization(conn, user_with_org)

        conn
        |> assign(:current_user, user_with_org)
        |> assign(:current_organization, organization)
    end
  end

  @doc """
  Ensures the user can only access resources belonging to their organization.
  Returns 404 if the resource doesn't belong to the user's organization.
  """
  def require_organization_resource(conn, organization_id) do
    current_organization = conn.assigns[:current_organization]

    if current_organization && current_organization.id == organization_id do
      conn
    else
      conn
      |> put_status(:not_found)
      |> put_view(AuthifyWeb.ErrorHTML)
      |> render(:"404")
      |> halt()
    end
  end

  @doc """
  Ensures the user is an admin of their organization.
  """
  def require_admin(conn, _opts \\ []) do
    current_user = conn.assigns[:current_user]
    current_organization = conn.assigns[:current_organization]

    if current_user && current_organization &&
         (Authify.Accounts.User.super_admin?(current_user) ||
            Authify.Accounts.User.admin?(current_user, current_organization.id)) do
      conn
    else
      conn
      |> put_flash(:error, "Access denied. Admin privileges required.")
      |> redirect(to: "/#{current_organization.slug}/dashboard")
      |> halt()
    end
  end

  @doc """
  Ensures the user is a super admin (global Authify admin).
  """
  def require_super_admin(conn, _opts \\ []) do
    current_user = conn.assigns[:current_user]
    current_organization = conn.assigns[:current_organization]

    if current_user && Authify.Accounts.User.super_admin?(current_user) do
      conn
    else
      conn
      |> put_flash(:error, "Access denied. Super admin privileges required.")
      |> redirect(to: "/#{current_organization.slug}/dashboard")
      |> halt()
    end
  end

  # Helper function to get the current organization, respecting session-based switching
  # Returns {conn, organization} tuple
  defp get_current_organization(conn, user) do
    case get_session(conn, :current_organization_id) do
      nil ->
        # No session override, use user's default organization
        {conn, preload_organization_config(user.organization)}

      organization_id when is_integer(organization_id) ->
        # Check if user can access this organization
        if can_access_organization?(user, organization_id) do
          case Accounts.get_organization(organization_id) do
            nil ->
              # Organization was deleted, clear the session and use default
              conn = delete_session(conn, :current_organization_id)
              {conn, preload_organization_config(user.organization)}

            organization ->
              {conn, preload_organization_config(organization)}
          end
        else
          # User can't access the requested organization, fall back to default
          {conn, preload_organization_config(user.organization)}
        end

      _ ->
        # Invalid session data, use default
        {conn, preload_organization_config(user.organization)}
    end
  end

  # Preload organization configuration for better performance
  # This reduces database queries when accessing rate limits and other settings
  defp preload_organization_config(organization) do
    Authify.Repo.preload(organization, configuration: :configuration_values)
  end

  # Check if a user can access a specific organization
  defp can_access_organization?(user, organization_id) do
    cond do
      # User's primary organization
      user.organization_id == organization_id ->
        true

      # Super admins can access any organization
      Authify.Accounts.User.super_admin?(user) ->
        true

      # Otherwise, no access
      true ->
        false
    end
  end
end
