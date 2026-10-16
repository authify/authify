defmodule AuthifyWeb.Plugs.EnforcePasswordReset do
  @moduledoc """
  Confines users who must change their password to the password-change page.

  This plug runs after `Guardian.Plug.LoadResource` in
  `AuthifyWeb.Auth.Pipeline`, so it covers every authenticated browser entry
  point: organization pages, the admin and super-admin areas, the OAuth
  authorize endpoint, and SAML SSO. Unauthenticated requests are left untouched.

  While `password_reset_required` is set, only the self-service password page,
  the emailed password-reset flow, and logout remain reachable; every other
  request is redirected to the password page.
  """

  import Plug.Conn
  import Phoenix.Controller

  alias Authify.Accounts
  alias Authify.Accounts.User
  alias Authify.Guardian

  # Exact suffixes that remain reachable while a reset is pending.
  @allowed_path_suffixes ["/profile/password", "/logout"]

  # Prefixes that remain reachable (the emailed reset flow lives under here).
  @allowed_path_prefixes ["/password_reset"]

  def init(opts), do: opts

  def call(conn, _opts) do
    case Guardian.Plug.current_resource(conn) do
      %User{} = user ->
        if User.password_reset_required?(user) and not allowed_path?(conn.request_path) do
          enforce(conn, user)
        else
          conn
        end

      _ ->
        conn
    end
  end

  defp enforce(conn, user) do
    conn =
      case organization_slug(conn, user) do
        nil ->
          # No organization context to redirect to; sign out rather than risk a
          # redirect loop back to a page that would be blocked again.
          conn
          |> Guardian.Plug.sign_out()
          |> put_flash(:error, "Please sign in to continue.")
          |> redirect(to: "/login")

        slug ->
          conn
          |> put_flash(:warning, "You must change your password before continuing.")
          |> redirect(to: "/#{slug}/profile/password")
      end

    halt(conn)
  end

  defp allowed_path?(path) do
    Enum.any?(@allowed_path_suffixes, &String.ends_with?(path, &1)) or
      Enum.any?(@allowed_path_prefixes, &String.starts_with?(path, &1))
  end

  defp organization_slug(conn, user) do
    conn.path_params["org_slug"] ||
      session_organization_slug(conn) ||
      user_organization_slug(user)
  end

  defp session_organization_slug(conn) do
    case get_session(conn, :current_organization_id) do
      id when is_integer(id) -> slug_for_organization(id)
      _ -> nil
    end
  end

  defp user_organization_slug(%User{organization_id: id}) when is_integer(id) do
    slug_for_organization(id)
  end

  defp user_organization_slug(_), do: nil

  defp slug_for_organization(id) do
    case Accounts.get_organization(id) do
      %{slug: slug} -> slug
      _ -> nil
    end
  end
end
