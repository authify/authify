defmodule AuthifyWeb.MfaController do
  use AuthifyWeb, :controller

  alias Authify.{Accounts, MFA, Repo}
  alias Authify.Accounts.User
  alias AuthifyWeb.Helpers.AuditHelper

  # ============================================================================
  # Setup Flow (Authenticated Users)
  # ============================================================================

  @doc """
  Display QR code and setup form for TOTP enrollment.
  Handles both voluntary setup (authenticated users) and mandatory setup (pending users).
  """
  def setup(conn, _params) do
    case get_setup_context(conn) do
      {:ok, user, organization} ->
        render_setup_form(conn, user, organization)

      {:error, conn} ->
        conn
    end
  end

  defp render_setup_form(conn, current_user, organization) do
    if User.totp_enabled?(current_user) do
      conn
      |> put_flash(:info, "Multi-factor authentication is already enabled.")
      |> redirect(to: ~p"/#{organization.slug}/profile/mfa")
    else
      # Generate TOTP secret
      case MFA.setup_totp(current_user) do
        {:ok, secret} ->
          # Generate TOTP URI
          totp_uri = generate_totp_uri(current_user, secret, organization)

          # Generate QR code from URI
          qr_code_data_uri = generate_qr_code(totp_uri)

          # Format secret for manual entry
          manual_entry_key = format_secret_for_manual_entry(secret)

          # Store secret in session temporarily (for verification)
          current_user_with_emails = Authify.Repo.preload(current_user, :emails)

          conn
          |> put_session(:mfa_setup_secret, secret)
          |> render(:setup,
            user: current_user_with_emails,
            user_email: User.get_primary_email_value(current_user_with_emails),
            organization: organization,
            secret: secret,
            totp_uri: totp_uri,
            qr_code_data_uri: qr_code_data_uri,
            manual_entry_key: manual_entry_key,
            error: nil
          )

        {:error, :totp_already_enabled} ->
          conn
          |> put_flash(:error, "Multi-factor authentication is already enabled.")
          |> redirect(to: ~p"/#{organization.slug}/profile/mfa")
      end
    end
  end

  @doc """
  Complete TOTP setup by verifying the code and enabling TOTP.
  Returns backup codes on success.
  """
  def complete_setup(conn, %{"verification_code" => code}) do
    case get_setup_context(conn) do
      {:ok, user, organization} ->
        verify_and_complete_setup(conn, user, organization, code)

      {:error, conn} ->
        conn
    end
  end

  defp verify_and_complete_setup(conn, current_user, organization, code) do
    # Retrieve secret from session
    case get_session(conn, :mfa_setup_secret) do
      nil ->
        conn
        |> put_flash(:error, "Setup session expired. Please start over.")
        |> redirect(to: ~p"/#{organization.slug}/profile/mfa/setup")

      secret ->
        # Verify and complete setup
        case MFA.complete_totp_setup(current_user, code, secret) do
          {:ok, updated_user, backup_codes} ->
            handle_setup_success(conn, current_user, updated_user, organization, backup_codes)

          {:error, :invalid_verification_code} ->
            handle_invalid_code(conn, current_user, organization, secret)

          {:error, _changeset} ->
            handle_setup_error(conn, current_user, organization, secret)
        end
    end
  end

  defp handle_setup_success(conn, current_user, updated_user, organization, backup_codes) do
    # Audit log
    AuditHelper.log_mfa_enabled(conn, current_user, extra_metadata: %{"source" => "web"})

    # Check if this was a mandatory MFA setup
    mfa_setup_required = get_session(conn, :mfa_setup_required)

    # Clear MFA setup session flags
    conn =
      conn
      |> delete_session(:mfa_setup_secret)
      |> delete_session(:mfa_setup_required)
      |> delete_session(:mfa_pending_user_id)
      |> delete_session(:mfa_pending_organization_id)

    if mfa_setup_required do
      # Mandatory setup complete - sign user in and show backup codes
      conn
      |> Authify.Guardian.Plug.sign_in(updated_user)
      |> put_session(:current_organization_id, organization.id)
      |> put_flash(
        :info,
        "Multi-factor authentication has been successfully enabled! Please save your backup codes before continuing."
      )
      |> render(:backup_codes,
        user: updated_user,
        organization: organization,
        backup_codes: backup_codes,
        show_download: true,
        mandatory_setup: true
      )
    else
      # Voluntary setup - show backup codes
      conn
      |> put_flash(
        :info,
        "Multi-factor authentication has been successfully enabled! Please save your backup codes."
      )
      |> render(:backup_codes,
        user: updated_user,
        organization: organization,
        backup_codes: backup_codes,
        show_download: true,
        mandatory_setup: false
      )
    end
  end

  defp handle_invalid_code(conn, current_user, organization, secret) do
    render_setup_with_error(
      conn,
      current_user,
      organization,
      secret,
      "Invalid verification code. Please try again.",
      "Invalid verification code"
    )
  end

  defp handle_setup_error(conn, current_user, organization, secret) do
    render_setup_with_error(
      conn,
      current_user,
      organization,
      secret,
      "Failed to enable MFA. Please try again.",
      "Setup failed"
    )
  end

  defp render_setup_with_error(conn, current_user, organization, secret, flash_message, error) do
    current_user_with_emails = Authify.Repo.preload(current_user, :emails)
    totp_uri = generate_totp_uri(current_user_with_emails, secret, organization)
    qr_code_data_uri = generate_qr_code(totp_uri)
    manual_entry_key = format_secret_for_manual_entry(secret)

    conn
    |> put_flash(:error, flash_message)
    |> render(:setup,
      user: current_user_with_emails,
      user_email: User.get_primary_email_value(current_user_with_emails),
      organization: organization,
      secret: secret,
      totp_uri: totp_uri,
      qr_code_data_uri: qr_code_data_uri,
      manual_entry_key: manual_entry_key,
      error: error
    )
  end

  # ============================================================================
  # Verification Flow (During Login - Partially Authenticated)
  # ============================================================================

  @doc """
  Display TOTP verification form during login.
  Requires mfa_pending_user_id in session.
  """
  def verify_form(conn, _params) do
    case get_session(conn, :mfa_pending_user_id) do
      nil ->
        conn
        |> put_flash(:error, "Please login first.")
        |> redirect(to: ~p"/login")

      user_id ->
        user = Repo.get(User, user_id) |> Repo.preload(:organization)
        organization_id = get_session(conn, :mfa_pending_organization_id)
        organization = Repo.get(Accounts.Organization, organization_id)

        # Check for active lockout
        case MFA.check_lockout(user) do
          {:ok, :no_lockout} ->
            render(conn, :verify_form,
              user: user,
              organization: organization,
              error: nil,
              attempts_remaining: nil
            )

          {:error, {:locked, _locked_until}} ->
            conn
            |> redirect(to: ~p"/mfa/locked")
        end
    end
  end

  @doc """
  Process TOTP verification during login.
  Handles both TOTP codes and backup codes.
  """
  def verify_code(conn, params) do
    case load_mfa_session(conn) do
      {:error, message} ->
        conn
        |> put_flash(:error, message)
        |> redirect(to: ~p"/login")

      {:ok, user, organization} ->
        handle_mfa_verification(conn, params, user, organization)
    end
  end

  @doc """
  Display lockout message when user has exceeded failed attempts.
  """
  def locked(conn, _params) do
    user_id = get_session(conn, :mfa_pending_user_id)

    case user_id do
      nil ->
        conn
        |> put_flash(:error, "Please login first.")
        |> redirect(to: ~p"/login")

      uid ->
        user = Repo.get(User, uid)

        case MFA.check_lockout(user) do
          {:error, {:locked, locked_until}} ->
            render(conn, :locked, locked_until: locked_until)

          {:ok, :no_lockout} ->
            conn
            |> put_flash(:info, "Lockout has expired. You may try again.")
            |> redirect(to: ~p"/mfa/verify")
        end
    end
  end

  @doc """
  Begin WebAuthn authentication by generating a challenge.
  Returns JSON with authentication options for the client.
  """
  def webauthn_authenticate_begin(conn, _params) do
    case load_mfa_session(conn) do
      {:error, _message} ->
        json(conn, %{success: false, error: "No active MFA session"})

      {:ok, user, _organization} ->
        # Get authentication options from WebAuthn context
        opts = [
          ip_address: get_client_ip(conn),
          user_agent: get_req_header(conn, "user-agent") |> List.first()
        ]

        case MFA.WebAuthn.begin_authentication(user, opts) do
          {:ok, %{challenge: challenge, options: options}} ->
            # Store challenge in session
            conn
            |> put_session(:webauthn_authentication_challenge, challenge)
            |> json(%{success: true, options: options})

          {:error, :no_credentials} ->
            json(conn, %{success: false, error: "No security keys registered"})

          {:error, _reason} ->
            json(conn, %{success: false, error: "Failed to generate challenge"})
        end
    end
  end

  @doc """
  Complete WebAuthn authentication by verifying the assertion response.
  """
  def webauthn_authenticate_complete(conn, params) do
    with {:ok, user, organization} <- load_mfa_session(conn),
         {:ok, challenge} <- get_authentication_challenge(conn),
         conn <- assign_user_and_org(conn, user, organization),
         {:allow, _} <- MFA.check_rate_limit(user, organization) do
      handle_webauthn_assertion(conn, user, organization, challenge, params)
    else
      {:error, message} ->
        json(conn, %{success: false, error: message})

      {:deny, _locked_until} ->
        json(conn, %{
          success: false,
          error: "Too many failed attempts. Your account has been temporarily locked."
        })
    end
  end

  # ============================================================================
  # Management Flow (Authenticated Users)
  # ============================================================================

  @doc """
  Show MFA status and management options.
  """
  def show(conn, _params) do
    current_user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    backup_codes_count = MFA.backup_codes_count(current_user)
    trusted_devices = MFA.list_trusted_devices(current_user)
    webauthn_credentials = MFA.WebAuthn.list_credentials(current_user)

    render(conn, :show,
      user: current_user,
      organization: organization,
      backup_codes_count: backup_codes_count,
      trusted_devices: trusted_devices,
      webauthn_credentials: webauthn_credentials
    )
  end

  @doc """
  Disable TOTP for user (requires password re-authentication).
  """
  def disable(conn, %{"password" => password}) do
    current_user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    # Verify password
    case Accounts.authenticate_user(
           User.get_primary_email_value(current_user),
           password,
           organization.id
         ) do
      {:ok, _user} ->
        # Disable TOTP
        case MFA.disable_totp(current_user) do
          {:ok, _updated_user} ->
            # Audit log
            AuditHelper.log_mfa_disabled(conn, current_user, extra_metadata: %{"source" => "web"})

            conn
            |> put_flash(:info, "Multi-factor authentication has been disabled.")
            |> redirect(to: ~p"/#{organization.slug}/profile")

          {:error, _} ->
            conn
            |> put_flash(:error, "Failed to disable MFA. Please try again.")
            |> redirect(to: ~p"/#{organization.slug}/profile/mfa")
        end

      {:error, _} ->
        conn
        |> put_flash(:error, "Invalid password. Please try again.")
        |> redirect(to: ~p"/#{organization.slug}/profile/mfa")
    end
  end

  def disable(conn, _params) do
    organization = conn.assigns.current_organization

    conn
    |> put_flash(:error, "Password is required to disable MFA.")
    |> redirect(to: ~p"/#{organization.slug}/profile/mfa")
  end

  # ============================================================================
  # Backup Codes
  # ============================================================================

  @doc """
  Display backup codes after regeneration.
  """
  def backup_codes(conn, _params) do
    current_user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    render(conn, :backup_codes,
      user: current_user,
      organization: organization,
      backup_codes: [],
      show_download: false
    )
  end

  @doc """
  Regenerate backup codes for user.
  """
  def regenerate_codes(conn, _params) do
    current_user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    case MFA.regenerate_backup_codes(current_user) do
      {:ok, _updated_user, backup_codes} ->
        # Audit log
        AuditHelper.log_mfa_backup_codes_regenerated(conn, current_user,
          extra_metadata: %{"source" => "web"}
        )

        conn
        |> put_flash(
          :info,
          "New backup codes have been generated. Please save them securely."
        )
        |> render(:backup_codes,
          user: current_user,
          organization: organization,
          backup_codes: backup_codes,
          show_download: true
        )

      {:error, _} ->
        conn
        |> put_flash(:error, "Failed to regenerate backup codes. Please try again.")
        |> redirect(to: ~p"/#{organization.slug}/profile/mfa")
    end
  end

  # ============================================================================
  # Trusted Devices
  # ============================================================================

  @doc """
  List all trusted devices for user.
  """
  def list_devices(conn, _params) do
    current_user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    devices = MFA.list_trusted_devices(current_user)

    render(conn, :devices,
      user: current_user,
      organization: organization,
      devices: devices
    )
  end

  @doc """
  Revoke a specific trusted device.
  """
  def revoke_device(conn, %{"id" => device_id}) do
    current_user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    {device_id_int, _} = Integer.parse(device_id)

    case MFA.revoke_trusted_device(device_id_int) do
      {:ok, _device} ->
        # Audit log
        AuditHelper.log_mfa_device_revoked(conn, current_user,
          extra_metadata: %{"source" => "web", "device_id" => device_id_int}
        )

        conn
        |> put_flash(:info, "Trusted device has been revoked.")
        |> redirect(to: ~p"/#{organization.slug}/profile/mfa/devices")

      {:error, :not_found} ->
        conn
        |> put_flash(:error, "Device not found.")
        |> redirect(to: ~p"/#{organization.slug}/profile/mfa/devices")
    end
  end

  @doc """
  Revoke all trusted devices for user.
  """
  def revoke_all_devices(conn, _params) do
    current_user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    {:ok, count} = MFA.revoke_all_trusted_devices(current_user)

    # Audit log
    AuditHelper.log_mfa_all_devices_revoked(conn, current_user,
      extra_metadata: %{"source" => "web", "devices_count" => count}
    )

    conn
    |> put_flash(:info, "All trusted devices have been revoked (#{count} devices).")
    |> redirect(to: ~p"/#{organization.slug}/profile/mfa")
  end

  # ============================================================================
  # Private Helper Functions
  # ============================================================================

  defp load_mfa_session(conn) do
    user_id = get_session(conn, :mfa_pending_user_id)
    organization_id = get_session(conn, :mfa_pending_organization_id)

    case {user_id, organization_id} do
      {nil, _} ->
        {:error, "Please login first."}

      {_, nil} ->
        {:error, "Session invalid. Please login again."}

      {uid, oid} ->
        user = Repo.get(User, uid) |> Repo.preload(:organization)
        organization = Repo.get(Accounts.Organization, oid)
        {:ok, user, organization}
    end
  end

  defp handle_mfa_verification(conn, params, user, organization) do
    code = params["totp_code"] || params["backup_code"] || ""
    remember_device = params["remember_device"] == "true"
    use_backup = params["use_backup"] == "true"

    # Assign user and organization to conn for audit logging
    conn =
      conn
      |> assign(:current_user, user)
      |> assign(:current_organization, organization)

    # Check rate limit before verifying
    case MFA.check_rate_limit(user, organization) do
      {:deny, _locked_until} ->
        # Rate limit exceeded, redirect to lockout page
        conn
        |> put_flash(
          :error,
          "Too many failed attempts. Your account has been temporarily locked."
        )
        |> redirect(to: ~p"/mfa/locked")

      {:allow, remaining_attempts} ->
        # Rate limit OK, verify code
        result =
          if use_backup do
            MFA.verify_backup_code(user, code)
          else
            MFA.verify_totp(user, code)
          end

        handle_verification_result(
          conn,
          result,
          user,
          organization,
          remember_device,
          use_backup,
          remaining_attempts
        )
    end
  end

  defp handle_verification_result(
         conn,
         {:ok, updated_user},
         _user,
         organization,
         remember_device,
         use_backup,
         _remaining_attempts
       ) do
    # Successful verification - clear rate limit and complete login
    MFA.clear_rate_limit(updated_user)

    device_token =
      if remember_device do
        create_trusted_device_token(conn, updated_user)
      else
        nil
      end

    # Audit log
    AuditHelper.log_mfa_verified(conn, updated_user,
      extra_metadata: %{
        "source" => "web",
        "method" => if(use_backup, do: "backup_code", else: "totp"),
        "device_trusted" => remember_device
      }
    )

    conn =
      if device_token do
        put_session(conn, :mfa_trusted_device_token, device_token)
      else
        conn
      end

    # Sign in and redirect
    conn
    |> Authify.Guardian.Plug.sign_in(updated_user)
    |> put_session(:current_organization_id, organization.id)
    |> clear_mfa_session()
    |> put_flash(:info, "Welcome back!")
    |> redirect(to: get_dashboard_path_for_user(updated_user, organization))
  end

  defp handle_verification_result(
         conn,
         {:error, :invalid_code},
         user,
         organization,
         _remember_device,
         use_backup,
         remaining_attempts
       ) do
    # Failed verification
    AuditHelper.log_mfa_failed(conn, user,
      extra_metadata: %{
        "source" => "web",
        "method" => if(use_backup, do: "backup_code", else: "totp"),
        "attempts_remaining" => remaining_attempts - 1
      }
    )

    error_message =
      if remaining_attempts > 1 do
        "Invalid code. #{remaining_attempts - 1} attempts remaining."
      else
        "Invalid code. This is your last attempt before lockout."
      end

    conn
    |> put_flash(:error, error_message)
    |> render(:verify_form,
      user: user,
      organization: organization,
      error: "Invalid code",
      attempts_remaining: remaining_attempts - 1
    )
  end

  defp handle_verification_result(
         conn,
         {:error, :totp_not_enabled},
         _user,
         _organization,
         _remember_device,
         _use_backup,
         _remaining_attempts
       ) do
    conn
    |> put_flash(:error, "Multi-factor authentication is not enabled.")
    |> redirect(to: ~p"/login")
  end

  defp handle_verification_result(
         conn,
         {:error, :no_codes},
         user,
         organization,
         _remember_device,
         _use_backup,
         remaining_attempts
       ) do
    conn
    |> put_flash(:error, "No backup codes available.")
    |> render(:verify_form,
      user: user,
      organization: organization,
      error: "No backup codes available",
      attempts_remaining: remaining_attempts
    )
  end

  defp handle_verification_result(
         conn,
         _error,
         user,
         organization,
         _remember_device,
         _use_backup,
         remaining_attempts
       ) do
    conn
    |> put_flash(:error, "Verification failed. Please try again.")
    |> render(:verify_form,
      user: user,
      organization: organization,
      error: "Verification failed",
      attempts_remaining: remaining_attempts
    )
  end

  defp generate_totp_uri(user, secret, organization) do
    # Format: otpauth://totp/Authify:user@example.com?secret=BASE32&issuer=OrgName
    label = "#{organization.name}:#{User.get_primary_email_value(user)}"
    issuer = organization.name
    # Base32-encode the binary secret for the URI (without padding per TOTP spec)
    base32_secret = Base.encode32(secret, padding: false)

    "otpauth://totp/#{URI.encode(label)}?secret=#{base32_secret}&issuer=#{URI.encode(issuer)}"
  end

  defp generate_qr_code(uri) do
    # Generate QR code as PNG data URI from the otpauth:// URI
    uri
    |> EQRCode.encode()
    |> EQRCode.png()
    |> Base.encode64()
  end

  defp format_secret_for_manual_entry(secret) do
    # Base32-encode the binary secret first, then format as groups of 4 for readability
    secret
    |> Base.encode32(padding: false)
    |> String.graphemes()
    |> Enum.chunk_every(4)
    |> Enum.map_join(" ", &Enum.join/1)
  end

  defp create_trusted_device_token(conn, user) do
    device_info = %{
      ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
      user_agent: Plug.Conn.get_req_header(conn, "user-agent") |> List.first()
    }

    case MFA.create_trusted_device(user, device_info) do
      {:ok, _device, token} ->
        token

      {:error, _} ->
        nil
    end
  end

  defp clear_mfa_session(conn) do
    conn
    |> delete_session(:mfa_pending_user_id)
    |> delete_session(:mfa_pending_organization_id)
    |> delete_session(:mfa_pending_timestamp)
    |> delete_session(:mfa_setup_secret)
  end

  # Determines the context for MFA setup (mandatory vs voluntary)
  # Returns {:ok, user, organization} or {:error, conn_with_redirect}
  defp get_setup_context(conn) do
    mfa_setup_required = get_session(conn, :mfa_setup_required)

    if mfa_setup_required do
      # Mandatory setup - load user from session
      user_id = get_session(conn, :mfa_pending_user_id)
      org_id = get_session(conn, :mfa_pending_organization_id)

      if user_id && org_id do
        user = Accounts.get_user!(user_id)
        org = Accounts.get_organization!(org_id)
        {:ok, user, org}
      else
        # Session expired, redirect to login
        conn =
          conn
          |> put_flash(:error, "Session expired. Please log in again.")
          |> redirect(to: ~p"/")
          |> halt()

        {:error, conn}
      end
    else
      # Voluntary setup - use authenticated user
      {:ok, conn.assigns.current_user, conn.assigns.current_organization}
    end
  end

  defp get_dashboard_path_for_user(user, organization) do
    # Check if user is admin in current organization or global admin
    if Accounts.User.admin?(user, organization.id) or Accounts.User.global_admin?(user) do
      ~p"/#{organization.slug}/dashboard"
    else
      ~p"/#{organization.slug}/user/dashboard"
    end
  end

  defp get_client_ip(conn) do
    case Plug.Conn.get_req_header(conn, "x-forwarded-for") do
      [ip | _] -> ip
      _ -> to_string(:inet_parse.ntoa(conn.remote_ip))
    end
  end

  defp create_and_store_trusted_device(conn, user) do
    device_token = create_trusted_device_token(conn, user)

    if device_token do
      put_session(conn, :mfa_trusted_device_token, device_token)
    else
      conn
    end
  end

  defp complete_mfa_login(conn, user, organization) do
    # Clear rate limit on successful login
    MFA.clear_rate_limit(user)

    # Sign in and set organization
    conn
    |> Authify.Guardian.Plug.sign_in(user)
    |> put_session(:current_organization_id, organization.id)
    |> clear_mfa_session()
  end

  defp redirect_after_mfa_success(organization) do
    "/#{organization.slug}/dashboard"
  end

  defp get_authentication_challenge(conn) do
    case get_session(conn, :webauthn_authentication_challenge) do
      nil -> {:error, "No active authentication challenge"}
      challenge -> {:ok, challenge}
    end
  end

  defp assign_user_and_org(conn, user, organization) do
    conn
    |> assign(:current_user, user)
    |> assign(:current_organization, organization)
  end

  defp handle_webauthn_assertion(conn, user, organization, challenge, params) do
    assertion_response = params["assertionResponse"]
    remember_device = params["rememberDevice"] == true

    case MFA.WebAuthn.complete_authentication(user, assertion_response, challenge) do
      {:ok, credential} ->
        handle_successful_webauthn_auth(conn, user, organization, credential, remember_device)

      {:error, reason} ->
        handle_failed_webauthn_auth(conn, user, reason)
    end
  end

  defp handle_successful_webauthn_auth(conn, user, organization, credential, remember_device) do
    conn = delete_session(conn, :webauthn_authentication_challenge)

    conn =
      if remember_device do
        create_and_store_trusted_device(conn, user)
      else
        conn
      end

    AuditHelper.log_mfa_verified(conn, user,
      extra_metadata: %{
        "source" => "web",
        "method" => "webauthn",
        "credential_id" => credential.id,
        "credential_name" => credential.name
      }
    )

    conn = complete_mfa_login(conn, user, organization)

    json(conn, %{
      success: true,
      redirect_url: redirect_after_mfa_success(organization)
    })
  end

  defp handle_failed_webauthn_auth(conn, user, reason) do
    AuditHelper.log_mfa_failed(conn, user,
      extra_metadata: %{
        "source" => "web",
        "method" => "webauthn",
        "reason" => inspect(reason)
      }
    )

    json(conn, %{
      success: false,
      error: format_webauthn_error(reason)
    })
  end

  defp format_webauthn_error(:invalid_challenge), do: "Invalid or expired challenge"
  defp format_webauthn_error(:challenge_already_used), do: "Challenge has already been used"
  defp format_webauthn_error(:challenge_expired), do: "Challenge has expired"
  defp format_webauthn_error(:challenge_mismatch), do: "Challenge verification failed"

  defp format_webauthn_error(:invalid_sign_count),
    do: "Security key may be cloned (invalid sign count)"

  defp format_webauthn_error(:credential_not_found), do: "Security key not recognized"
  defp format_webauthn_error(:credential_not_owned), do: "Security key not owned by this user"
  defp format_webauthn_error(:decryption_failed), do: "Failed to decrypt credential data"
  defp format_webauthn_error(_), do: "Authentication failed"
end
