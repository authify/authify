defmodule AuthifyWeb.SessionController do
  use AuthifyWeb, :controller

  alias Authify.Accounts
  alias Authify.AuditLog
  alias Authify.Configurations
  alias Authify.Guardian

  def new(conn, params) do
    # Clear any existing session when showing login form
    conn = Guardian.Plug.sign_out(conn)
    changeset = Accounts.change_user_registration(%Authify.Accounts.User{})
    # Pass org_slug from query params to pre-fill the form
    org_slug = params["org_slug"]

    # Check if organization registration is enabled
    allow_org_registration = Configurations.get_global_setting(:allow_organization_registration)

    render(conn, :new,
      changeset: changeset,
      org_slug: org_slug,
      allow_org_registration: allow_org_registration
    )
  end

  def create(conn, %{
        "login" => %{"email" => email, "password" => password, "organization_slug" => org_slug}
      }) do
    # Check if organization registration is enabled for error rendering
    allow_org_registration = Configurations.get_global_setting(:allow_organization_registration)

    case Accounts.get_organization_by_slug(org_slug) do
      nil ->
        conn
        |> put_flash(:error, "Organization not found.")
        |> render(:new,
          changeset: Accounts.change_user_registration(%Authify.Accounts.User{}),
          org_slug: org_slug,
          allow_org_registration: allow_org_registration
        )

      organization ->
        case Accounts.authenticate_user(email, password, organization.id) do
          {:ok, user} ->
            # Log successful login
            AuditLog.log_event_async(:login_success, %{
              organization_id: organization.id,
              actor_type: "user",
              actor_id: user.id,
              actor_name: "#{user.first_name} #{user.last_name}",
              outcome: "success",
              ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
              user_agent: Plug.Conn.get_req_header(conn, "user-agent") |> List.first()
            })

            # Clear any existing session before signing in, then set the selected organization
            conn
            |> Guardian.Plug.sign_out()
            |> Guardian.Plug.sign_in(user)
            |> put_session(:current_organization_id, organization.id)
            |> put_flash(:info, "Welcome back!")
            |> redirect(to: get_dashboard_path_for_user(user, organization))

          {:error, :invalid_password} ->
            # Log failed login attempt
            AuditLog.log_event_async(:login_failure, %{
              organization_id: organization.id,
              actor_type: "user",
              actor_name: email,
              outcome: "failure",
              ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
              user_agent: Plug.Conn.get_req_header(conn, "user-agent") |> List.first(),
              metadata: %{reason: "invalid_password", attempted_email: email}
            })

            conn
            |> put_flash(:error, "Invalid email or password.")
            |> render(:new,
              changeset: Accounts.change_user_registration(%Authify.Accounts.User{}),
              org_slug: org_slug,
              allow_org_registration: allow_org_registration
            )

          {:error, :user_not_found} ->
            # Log failed login attempt
            AuditLog.log_event_async(:login_failure, %{
              organization_id: organization.id,
              actor_type: "user",
              actor_name: email,
              outcome: "failure",
              ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
              user_agent: Plug.Conn.get_req_header(conn, "user-agent") |> List.first(),
              metadata: %{reason: "user_not_found", attempted_email: email}
            })

            conn
            |> put_flash(:error, "Invalid email or password.")
            |> render(:new,
              changeset: Accounts.change_user_registration(%Authify.Accounts.User{}),
              org_slug: org_slug,
              allow_org_registration: allow_org_registration
            )
        end
    end
  end

  def delete(conn, params) do
    current_user = conn.assigns.current_user
    slo_complete = params["slo_complete"]

    # Log logout event if user is present
    if current_user do
      AuditLog.log_event_async(:logout, %{
        organization_id: current_user.organization_id,
        actor_type: "user",
        actor_id: current_user.id,
        actor_name: "#{current_user.first_name} #{current_user.last_name}",
        outcome: "success",
        ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
        user_agent: Plug.Conn.get_req_header(conn, "user-agent") |> List.first(),
        metadata: %{saml_slo: slo_complete == "true"}
      })
    end

    # Sign out the user from Guardian
    conn = Guardian.Plug.sign_out(conn)

    # Check if this is part of SAML Single Logout completion
    if slo_complete == "true" do
      conn
      |> put_flash(:info, "You have been logged out from all connected applications.")
      |> redirect(to: ~p"/")
    else
      # Regular logout - check for active SAML sessions
      if current_user do
        active_saml_sessions = Authify.SAML.get_active_sessions_for_user(current_user)

        if Enum.empty?(active_saml_sessions) do
          # No SAML sessions, just do regular logout
          conn
          |> put_flash(:info, "You have been logged out.")
          |> redirect(to: ~p"/")
        else
          # SAML sessions exist, redirect to SAML SLO endpoint for coordination
          org_slug = current_user.organization.slug

          redirect(conn, to: "/#{org_slug}/saml/slo")
        end
      else
        # No current user
        conn
        |> put_flash(:info, "You have been logged out.")
        |> redirect(to: ~p"/")
      end
    end
  end

  # Determines the appropriate dashboard path based on user role and organization
  defp get_dashboard_path_for_user(user, organization) do
    # Load user organizations to check role
    user = Accounts.get_user_with_organizations!(user.id)

    # Check if user is an admin in this organization or global admin
    if admin_user?(user, organization) do
      ~p"/#{organization.slug}/dashboard"
    else
      ~p"/#{organization.slug}/user/dashboard"
    end
  end

  # Helper to determine if user has admin privileges
  defp admin_user?(user, organization) do
    # Check if user is admin in current organization or global admin
    Authify.Accounts.User.admin?(user, organization.id) or
      Authify.Accounts.User.global_admin?(user)
  end
end
