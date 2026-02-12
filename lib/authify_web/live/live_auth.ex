defmodule AuthifyWeb.LiveAuth do
  @moduledoc """
  LiveView on_mount hooks for authentication and authorization.

  These hooks provide similar functionality to the Plug-based auth system
  but are designed for LiveView components.

  ## Usage

      defmodule MyAppWeb.SomeLive do
        use MyAppWeb, :live_view

        on_mount {AuthifyWeb.LiveAuth, :ensure_authenticated}
        on_mount {AuthifyWeb.LiveAuth, :put_current_organization}
        ...
      end
  """

  import Phoenix.LiveView
  import Phoenix.Component

  alias Authify.Accounts
  alias Authify.Guardian

  @doc """
  Callback for LiveView on_mount hooks. Supports multiple mount hooks:

  - `:ensure_authenticated` - Ensures the user is authenticated via Guardian session
  - `:put_current_organization` - Sets up organization context for the current user
  - `:require_admin` - Ensures the user is an admin of their current organization
  - `:require_super_admin` - Ensures the user is a super admin (global Authify admin)
  """
  def on_mount(mount_type, params, session, socket)

  def on_mount(:ensure_authenticated, _params, session, socket) do
    case get_user_from_session(session) do
      nil ->
        socket =
          socket
          |> put_flash(:error, "You must be logged in to access this page.")
          |> redirect(to: "/login")

        {:halt, socket}

      user ->
        {:cont, assign(socket, :current_user, user)}
    end
  end

  def on_mount(:put_current_organization, _params, session, socket) do
    user = socket.assigns[:current_user]

    if user do
      # Load user with organization relationship
      user_with_org = Accounts.get_user_with_organizations!(user.id)
      organization = get_current_organization(session, user_with_org)

      socket =
        socket
        |> assign(:current_user, user_with_org)
        |> assign(:current_organization, organization)

      {:cont, socket}
    else
      # User not set, skip (ensure_authenticated should handle this)
      {:cont, socket}
    end
  end

  def on_mount(:require_admin, _params, _session, socket) do
    current_user = socket.assigns[:current_user]
    current_organization = socket.assigns[:current_organization]

    if current_user && current_organization &&
         (Accounts.User.super_admin?(current_user) ||
            Accounts.User.admin?(current_user, current_organization.id)) do
      {:cont, socket}
    else
      socket =
        socket
        |> put_flash(:error, "Access denied. Admin privileges required.")
        |> redirect(to: "/#{current_organization.slug}/dashboard")

      {:halt, socket}
    end
  end

  def on_mount(:require_super_admin, _params, _session, socket) do
    current_user = socket.assigns[:current_user]
    current_organization = socket.assigns[:current_organization]

    if current_user && Accounts.User.super_admin?(current_user) do
      {:cont, socket}
    else
      socket =
        socket
        |> put_flash(:error, "Access denied. Super admin privileges required.")
        |> redirect(to: "/#{current_organization.slug}/dashboard")

      {:halt, socket}
    end
  end

  # Private helpers

  defp get_user_from_session(%{"guardian_default_token" => token}) when is_binary(token) do
    case Guardian.resource_from_token(token) do
      {:ok, user, _claims} -> user
      {:error, _reason} -> nil
    end
  end

  defp get_user_from_session(_session), do: nil

  defp get_current_organization(session, user) do
    case Map.get(session, "current_organization_id") do
      nil ->
        # No session override, use user's default organization
        preload_organization_config(user.organization)

      organization_id when is_integer(organization_id) ->
        # Check if user can access this organization
        if can_access_organization?(user, organization_id) do
          case Accounts.get_organization(organization_id) do
            nil ->
              # Organization was deleted, use default
              preload_organization_config(user.organization)

            organization ->
              preload_organization_config(organization)
          end
        else
          # User can't access the requested organization, fall back to default
          preload_organization_config(user.organization)
        end

      _ ->
        # Invalid session data, use default
        preload_organization_config(user.organization)
    end
  end

  defp preload_organization_config(organization) do
    Authify.Repo.preload(organization, configuration: :configuration_values)
  end

  defp can_access_organization?(user, organization_id) do
    cond do
      # User's primary organization
      user.organization_id == organization_id ->
        true

      # Super admins can access any organization
      Accounts.User.super_admin?(user) ->
        true

      # Otherwise, no access
      true ->
        false
    end
  end
end
