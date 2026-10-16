defmodule AuthifyWeb.Auth.Navigation do
  @moduledoc """
  Provides shared post-authentication navigation and session logic.

  Centralizes logic that was previously duplicated across
  `AuthifyWeb.SessionController` and `AuthifyWeb.MfaController`, such as
  clearing MFA-related session keys, completing the MFA login flow, and
  computing the dashboard path a user should be redirected to after
  authentication.
  """

  use Phoenix.VerifiedRoutes,
    endpoint: AuthifyWeb.Endpoint,
    router: AuthifyWeb.Router

  import Plug.Conn

  alias Authify.Accounts.User
  alias Authify.MFA

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

  @doc """
  Returns the `{conn, destination}` a freshly-authenticated user should be sent
  to.

  Users flagged as requiring a password reset are always sent to the password
  change page, and any pending `return_to` destination is discarded so it cannot
  bypass the requirement. Everyone else resumes a pending `return_to` or lands
  on their dashboard.
  """
  def post_authentication_destination(conn, user, organization) do
    if User.password_reset_required?(user) do
      {delete_session(conn, :return_to), password_change_path(organization)}
    else
      AuthifyWeb.Auth.ReturnTo.destination(conn, dashboard_path_for_user(user, organization))
    end
  end

  @doc """
  Returns the `{flash_level, message}` to show after authentication.
  """
  def post_authentication_flash(user) do
    if User.password_reset_required?(user) do
      {:warning, "You must change your password before continuing."}
    else
      {:info, "Welcome back!"}
    end
  end

  @doc """
  Absolute path to the self-service password change page for an organization.
  """
  def password_change_path(organization) do
    ~p"/#{organization.slug}/profile/password"
  end

  @doc """
  Clears MFA-related session keys from the connection.

  Removes the pending user/organization ids, the pending timestamp, and any
  cached MFA setup secret. Used both during login completion and on logout
  to ensure no stale MFA state remains in the session.
  """
  def clear_mfa_session(conn) do
    conn
    |> delete_session(:mfa_pending_user_id)
    |> delete_session(:mfa_pending_organization_id)
    |> delete_session(:mfa_pending_timestamp)
    |> delete_session(:mfa_setup_secret)
  end

  @doc """
  Completes the MFA login flow for a successfully verified user.

  Clears the MFA rate limit for the user, signs them in via Guardian, stores
  the current organization id in the session, and clears any remaining MFA
  pending session keys. Returns the updated connection.
  """
  def complete_mfa_login(conn, user, organization) do
    MFA.clear_rate_limit(user)

    conn
    |> Authify.Guardian.Plug.sign_in(user)
    |> put_session(:current_organization_id, organization.id)
    |> clear_mfa_session()
  end
end
