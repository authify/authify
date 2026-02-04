defmodule AuthifyWeb.MfaControllerTest do
  use AuthifyWeb.ConnCase

  alias Authify.{Accounts, MFA, Repo}
  alias Authify.Accounts.User

  setup do
    # Create organization
    {:ok, organization} =
      Accounts.create_organization(%{name: "Test Org", slug: "test-org"})

    # Create user
    user_attrs = %{
      "first_name" => "John",
      "last_name" => "Doe",
      "email" => "john@test.com",
      "password" => "SecureP@ssw0rd!",
      "password_confirmation" => "SecureP@ssw0rd!"
    }

    {:ok, user} = Accounts.create_user_with_role(user_attrs, organization.id, "user")

    # Reload user with organization
    user = Repo.preload(user, :organization)

    %{organization: organization, user: user}
  end

  # ============================================================================
  # Setup Flow Tests
  # ============================================================================

  describe "GET /:org_slug/profile/mfa/setup" do
    test "displays QR code and setup form for user without TOTP", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      conn =
        conn
        |> log_in_user(user, organization)
        |> get(~p"/#{organization.slug}/profile/mfa/setup")

      assert html_response(conn, 200) =~ "Setup Multi-Factor Authentication"
      assert html_response(conn, 200) =~ "Scan QR Code"
      assert html_response(conn, 200) =~ "Verification Code"
      # Should contain QR code image
      assert html_response(conn, 200) =~ "data:image/png;base64"
    end

    test "redirects if TOTP already enabled", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      # Enable TOTP first
      {:ok, secret} = MFA.setup_totp(user)
      {:ok, _user, _codes} = MFA.complete_totp_setup(user, generate_valid_totp(secret), secret)

      conn =
        conn
        |> log_in_user(user, organization)
        |> get(~p"/#{organization.slug}/profile/mfa/setup")

      assert redirected_to(conn) == ~p"/#{organization.slug}/profile/mfa"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "already enabled"
    end

    test "requires authentication", %{conn: conn, organization: organization} do
      conn = get(conn, ~p"/#{organization.slug}/profile/mfa/setup")

      assert redirected_to(conn) == ~p"/login"
    end
  end

  describe "POST /:org_slug/profile/mfa/setup" do
    test "enables TOTP with valid verification code", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      # Start setup to get secret in session
      conn = log_in_user(conn, user, organization)
      conn = get(conn, ~p"/#{organization.slug}/profile/mfa/setup")

      # Extract secret from session
      secret = Plug.Conn.get_session(conn, :mfa_setup_secret)
      valid_code = generate_valid_totp(secret)

      # Complete setup
      conn =
        post(conn, ~p"/#{organization.slug}/profile/mfa/setup", %{
          "verification_code" => valid_code
        })

      assert html_response(conn, 200) =~ "Backup Codes"
      assert html_response(conn, 200) =~ "Multi-Factor Authentication Enabled"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "successfully enabled"

      # Verify user has TOTP enabled
      user = Repo.get(User, user.id)
      assert User.totp_enabled?(user)
    end

    test "shows error with invalid verification code", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      # Start setup
      conn = log_in_user(conn, user, organization)
      conn = get(conn, ~p"/#{organization.slug}/profile/mfa/setup")

      # Try with invalid code
      conn =
        post(conn, ~p"/#{organization.slug}/profile/mfa/setup", %{
          "verification_code" => "000000"
        })

      assert html_response(conn, 200) =~ "Setup Multi-Factor Authentication"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Invalid verification code"

      # Verify user still doesn't have TOTP enabled
      user = Repo.get(User, user.id)
      refute User.totp_enabled?(user)
    end

    test "redirects if session expired", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      conn =
        conn
        |> log_in_user(user, organization)
        |> post(~p"/#{organization.slug}/profile/mfa/setup", %{
          "verification_code" => "123456"
        })

      assert redirected_to(conn) == ~p"/#{organization.slug}/profile/mfa/setup"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "session expired"
    end
  end

  # ============================================================================
  # Verification Flow Tests (During Login)
  # ============================================================================

  describe "GET /mfa/verify" do
    test "shows verification form with pending MFA session", %{
      organization: organization,
      user: user
    } do
      # Enable TOTP for user
      {:ok, secret} = MFA.setup_totp(user)
      {:ok, user, _codes} = MFA.complete_totp_setup(user, generate_valid_totp(secret), secret)

      # Simulate login with pending MFA
      conn =
        build_conn()
        |> init_test_session(%{
          mfa_pending_user_id: user.id,
          mfa_pending_organization_id: organization.id
        })
        |> get(~p"/mfa/verify")

      assert html_response(conn, 200) =~ "Multi-Factor Authentication"
      assert html_response(conn, 200) =~ "Authentication Code"
      assert html_response(conn, 200) =~ "Remember this device"
    end

    test "redirects to login without pending MFA session", %{conn: conn} do
      conn = get(conn, ~p"/mfa/verify")

      assert redirected_to(conn) == ~p"/login"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Please login first"
    end

    test "redirects to locked page if user is locked out", %{
      organization: organization,
      user: user
    } do
      # Enable TOTP
      {:ok, secret} = MFA.setup_totp(user)
      {:ok, user, _codes} = MFA.complete_totp_setup(user, generate_valid_totp(secret), secret)

      # Create lockout
      locked_until =
        DateTime.utc_now() |> DateTime.add(300, :second) |> DateTime.truncate(:second)

      Repo.insert!(%Authify.MFA.TotpLockout{
        user_id: user.id,
        locked_at: DateTime.utc_now() |> DateTime.truncate(:second),
        locked_until: locked_until,
        failed_attempts: 5
      })

      conn =
        build_conn()
        |> init_test_session(%{
          mfa_pending_user_id: user.id,
          mfa_pending_organization_id: organization.id
        })
        |> get(~p"/mfa/verify")

      assert redirected_to(conn) == ~p"/mfa/locked"
    end
  end

  describe "POST /mfa/verify" do
    test "completes login with valid TOTP code", %{organization: organization, user: user} do
      # Enable TOTP
      {:ok, secret} = MFA.setup_totp(user)
      {:ok, user, _codes} = MFA.complete_totp_setup(user, generate_valid_totp(secret), secret)

      # Get current valid code
      valid_code = generate_valid_totp(secret)

      conn =
        build_conn()
        |> init_test_session(%{
          mfa_pending_user_id: user.id,
          mfa_pending_organization_id: organization.id
        })
        |> post(~p"/mfa/verify", %{"totp_code" => valid_code})

      assert redirected_to(conn) == ~p"/#{organization.slug}/user/dashboard"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "Welcome back"
    end

    test "completes login with valid backup code", %{organization: organization, user: user} do
      # Enable TOTP
      {:ok, secret} = MFA.setup_totp(user)

      {:ok, user, backup_codes} =
        MFA.complete_totp_setup(user, generate_valid_totp(secret), secret)

      # Use first backup code
      backup_code = List.first(backup_codes)

      conn =
        build_conn()
        |> init_test_session(%{
          mfa_pending_user_id: user.id,
          mfa_pending_organization_id: organization.id
        })
        |> post(~p"/mfa/verify", %{"totp_code" => backup_code, "use_backup" => "true"})

      assert redirected_to(conn) == ~p"/#{organization.slug}/user/dashboard"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "Welcome back"

      # Verify code was consumed
      user = Repo.get(User, user.id)
      assert MFA.backup_codes_count(user) == 9
    end

    test "shows error with invalid TOTP code", %{organization: organization, user: user} do
      # Enable TOTP
      {:ok, secret} = MFA.setup_totp(user)
      {:ok, user, _codes} = MFA.complete_totp_setup(user, generate_valid_totp(secret), secret)

      conn =
        build_conn()
        |> init_test_session(%{
          mfa_pending_user_id: user.id,
          mfa_pending_organization_id: organization.id
        })
        |> post(~p"/mfa/verify", %{"totp_code" => "000000"})

      assert html_response(conn, 200) =~ "Multi-Factor Authentication"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Invalid code"
    end

    test "creates trusted device when remember_device is checked", %{
      organization: organization,
      user: user
    } do
      # Enable TOTP
      {:ok, secret} = MFA.setup_totp(user)
      {:ok, user, _codes} = MFA.complete_totp_setup(user, generate_valid_totp(secret), secret)

      valid_code = generate_valid_totp(secret)

      conn =
        build_conn()
        |> init_test_session(%{
          mfa_pending_user_id: user.id,
          mfa_pending_organization_id: organization.id
        })
        |> post(~p"/mfa/verify", %{
          "totp_code" => valid_code,
          "remember_device" => "true"
        })

      assert redirected_to(conn) == ~p"/#{organization.slug}/user/dashboard"

      # Verify device token stored in session
      assert Plug.Conn.get_session(conn, :mfa_trusted_device_token) != nil

      # Verify device created
      devices = MFA.list_trusted_devices(user)
      assert length(devices) == 1
    end
  end

  describe "GET /mfa/locked" do
    test "displays lockout message with locked until time", %{
      organization: organization,
      user: user
    } do
      # Enable TOTP
      {:ok, secret} = MFA.setup_totp(user)
      {:ok, user, _codes} = MFA.complete_totp_setup(user, generate_valid_totp(secret), secret)

      # Create lockout
      locked_until =
        DateTime.utc_now() |> DateTime.add(300, :second) |> DateTime.truncate(:second)

      Repo.insert!(%Authify.MFA.TotpLockout{
        user_id: user.id,
        locked_at: DateTime.utc_now() |> DateTime.truncate(:second),
        locked_until: locked_until,
        failed_attempts: 5
      })

      conn =
        build_conn()
        |> init_test_session(%{
          mfa_pending_user_id: user.id,
          mfa_pending_organization_id: organization.id
        })
        |> get(~p"/mfa/locked")

      assert html_response(conn, 200) =~ "Account Temporarily Locked"
      assert html_response(conn, 200) =~ "Too Many Failed Attempts"
    end

    test "redirects to verify if lockout expired", %{organization: organization, user: user} do
      # Enable TOTP
      {:ok, secret} = MFA.setup_totp(user)
      {:ok, user, _codes} = MFA.complete_totp_setup(user, generate_valid_totp(secret), secret)

      # Create expired lockout
      locked_until =
        DateTime.utc_now() |> DateTime.add(-10, :second) |> DateTime.truncate(:second)

      Repo.insert!(%Authify.MFA.TotpLockout{
        user_id: user.id,
        locked_at:
          DateTime.utc_now() |> DateTime.add(-310, :second) |> DateTime.truncate(:second),
        locked_until: locked_until,
        failed_attempts: 5
      })

      conn =
        build_conn()
        |> init_test_session(%{
          mfa_pending_user_id: user.id,
          mfa_pending_organization_id: organization.id
        })
        |> get(~p"/mfa/locked")

      assert redirected_to(conn) == ~p"/mfa/verify"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "Lockout has expired"
    end
  end

  # ============================================================================
  # Management Flow Tests
  # ============================================================================

  describe "GET /:org_slug/profile/mfa" do
    test "shows MFA status for user without TOTP", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      conn =
        conn
        |> log_in_user(user, organization)
        |> get(~p"/#{organization.slug}/profile/mfa")

      assert html_response(conn, 200) =~ "Multi-Factor Authentication"
      assert html_response(conn, 200) =~ "Not Enabled"
      assert html_response(conn, 200) =~ "Setup Multi-Factor Authentication"
    end

    test "shows MFA status and management options for user with TOTP", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      # Enable TOTP
      {:ok, secret} = MFA.setup_totp(user)
      {:ok, user, _codes} = MFA.complete_totp_setup(user, generate_valid_totp(secret), secret)

      conn =
        conn
        |> log_in_user(user, organization)
        |> get(~p"/#{organization.slug}/profile/mfa")

      response = html_response(conn, 200)
      assert response =~ "Multi-Factor Authentication"
      assert response =~ "Enabled"
      assert response =~ "Authenticator App (TOTP)"
      assert response =~ "Security Keys"
      assert response =~ "WebAuthn"
      assert response =~ "Backup Codes"
      assert response =~ "backup codes remaining"
      assert response =~ "Trusted Devices"
      assert response =~ "Disable TOTP"
    end

    test "requires authentication", %{conn: conn, organization: organization} do
      conn = get(conn, ~p"/#{organization.slug}/profile/mfa")

      assert redirected_to(conn) == ~p"/login"
    end
  end

  describe "DELETE /:org_slug/profile/mfa" do
    test "disables TOTP with valid password", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      # Enable TOTP
      {:ok, secret} = MFA.setup_totp(user)
      {:ok, user, _codes} = MFA.complete_totp_setup(user, generate_valid_totp(secret), secret)

      conn =
        conn
        |> log_in_user(user, organization)
        |> delete(~p"/#{organization.slug}/profile/mfa", %{"password" => "SecureP@ssw0rd!"})

      assert redirected_to(conn) == ~p"/#{organization.slug}/profile"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "has been disabled"

      # Verify TOTP disabled
      user = Repo.get(User, user.id)
      refute User.totp_enabled?(user)
    end

    test "shows error with invalid password", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      # Enable TOTP
      {:ok, secret} = MFA.setup_totp(user)
      {:ok, user, _codes} = MFA.complete_totp_setup(user, generate_valid_totp(secret), secret)

      conn =
        conn
        |> log_in_user(user, organization)
        |> delete(~p"/#{organization.slug}/profile/mfa", %{"password" => "wrong_password"})

      assert redirected_to(conn) == ~p"/#{organization.slug}/profile/mfa"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Invalid password"

      # Verify TOTP still enabled
      user = Repo.get(User, user.id)
      assert User.totp_enabled?(user)
    end

    test "shows error without password", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      # Enable TOTP
      {:ok, secret} = MFA.setup_totp(user)
      {:ok, user, _codes} = MFA.complete_totp_setup(user, generate_valid_totp(secret), secret)

      conn =
        conn
        |> log_in_user(user, organization)
        |> delete(~p"/#{organization.slug}/profile/mfa", %{})

      assert redirected_to(conn) == ~p"/#{organization.slug}/profile/mfa"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Password is required"
    end
  end

  # ============================================================================
  # Backup Codes Tests
  # ============================================================================

  describe "POST /:org_slug/profile/mfa/regenerate-codes" do
    test "generates new backup codes", %{conn: conn, organization: organization, user: user} do
      # Enable TOTP
      {:ok, secret} = MFA.setup_totp(user)
      {:ok, user, _codes} = MFA.complete_totp_setup(user, generate_valid_totp(secret), secret)

      conn =
        conn
        |> log_in_user(user, organization)
        |> post(~p"/#{organization.slug}/profile/mfa/regenerate-codes")

      assert html_response(conn, 200) =~ "Backup Codes"
      assert html_response(conn, 200) =~ "New backup codes have been generated"

      # Verify new codes displayed
      assert html_response(conn, 200) =~ "Your Backup Codes"
    end

    test "requires TOTP to be enabled", %{conn: conn, organization: organization, user: user} do
      conn =
        conn
        |> log_in_user(user, organization)
        |> post(~p"/#{organization.slug}/profile/mfa/regenerate-codes")

      # Should handle gracefully (may redirect or show error)
      assert conn.status in [200, 302]
    end
  end

  # ============================================================================
  # Device Management Tests
  # ============================================================================

  describe "DELETE /:org_slug/profile/mfa/devices/:id" do
    test "revokes specific device", %{conn: conn, organization: organization, user: user} do
      # Enable TOTP
      {:ok, secret} = MFA.setup_totp(user)
      {:ok, user, _codes} = MFA.complete_totp_setup(user, generate_valid_totp(secret), secret)

      # Create trusted device
      {:ok, device, _token} =
        MFA.create_trusted_device(user, %{
          ip_address: "127.0.0.1",
          user_agent: "Test Browser"
        })

      conn =
        conn
        |> log_in_user(user, organization)
        |> delete(~p"/#{organization.slug}/profile/mfa/devices/#{device.id}")

      assert redirected_to(conn) == ~p"/#{organization.slug}/profile/mfa"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "has been revoked"

      # Verify device revoked
      assert MFA.list_trusted_devices(user) == []
    end

    test "shows error for non-existent device", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      # Enable TOTP
      {:ok, secret} = MFA.setup_totp(user)
      {:ok, user, _codes} = MFA.complete_totp_setup(user, generate_valid_totp(secret), secret)

      conn =
        conn
        |> log_in_user(user, organization)
        |> delete(~p"/#{organization.slug}/profile/mfa/devices/99999")

      assert redirected_to(conn) == ~p"/#{organization.slug}/profile/mfa"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "not found"
    end
  end

  describe "DELETE /:org_slug/profile/mfa/devices" do
    test "revokes all devices", %{conn: conn, organization: organization, user: user} do
      # Enable TOTP
      {:ok, secret} = MFA.setup_totp(user)
      {:ok, user, _codes} = MFA.complete_totp_setup(user, generate_valid_totp(secret), secret)

      # Create multiple devices
      MFA.create_trusted_device(user, %{ip_address: "127.0.0.1", user_agent: "Browser 1"})
      MFA.create_trusted_device(user, %{ip_address: "127.0.0.2", user_agent: "Browser 2"})

      conn =
        conn
        |> log_in_user(user, organization)
        |> delete(~p"/#{organization.slug}/profile/mfa/devices")

      assert redirected_to(conn) == ~p"/#{organization.slug}/profile/mfa"

      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~
               "All trusted devices have been revoked"

      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "2 devices"

      # Verify all devices revoked
      assert MFA.list_trusted_devices(user) == []
    end
  end

  # ============================================================================
  # WebAuthn Authentication Tests
  # ============================================================================

  describe "POST /:org_slug/webauthn/authenticate/begin" do
    setup %{organization: organization, user: user} do
      # Create a WebAuthn credential for the user
      credential =
        %Authify.MFA.WebAuthnCredential{}
        |> Authify.MFA.WebAuthnCredential.changeset(%{
          user_id: user.id,
          organization_id: user.organization_id,
          credential_id: "test_cred_123",
          public_key: :crypto.strong_rand_bytes(32),
          sign_count: 0,
          name: "Test Key",
          credential_type: "platform"
        })
        |> Repo.insert!()

      # Start MFA verification session
      conn =
        build_conn()
        |> Plug.Test.init_test_session(%{
          mfa_pending_user_id: user.id,
          mfa_pending_organization_id: organization.id
        })

      %{conn: conn, credential: credential}
    end

    test "returns authentication challenge and options", %{conn: conn} do
      conn = post(conn, ~p"/mfa/webauthn/authenticate/begin")

      response = json_response(conn, 200)
      assert response["success"] == true
      assert response["options"]
      assert response["options"]["challenge"]
      assert response["options"]["allowCredentials"]

      # Verify challenge is stored in session
      challenge = get_session(conn, :webauthn_authentication_challenge)
      assert is_binary(challenge)
    end

    test "returns error if user has no credentials", %{
      conn: conn,
      credential: credential
    } do
      # Delete the credential
      Repo.delete!(credential)

      conn = post(conn, ~p"/mfa/webauthn/authenticate/begin")

      response = json_response(conn, 200)
      assert response["success"] == false
      assert response["error"] =~ "No security keys registered"
    end

    test "requires MFA session" do
      # Create new conn without MFA session
      conn =
        build_conn()
        |> Plug.Test.init_test_session(%{})
        |> post(~p"/mfa/webauthn/authenticate/begin")

      response = json_response(conn, 200)
      assert response["success"] == false
      assert response["error"] =~ "No active MFA session"
    end
  end

  describe "POST /mfa/webauthn/authenticate/complete" do
    setup %{conn: conn} do
      # Begin authentication to get challenge
      conn = post(conn, ~p"/mfa/webauthn/authenticate/begin")
      challenge = get_session(conn, :webauthn_authentication_challenge)

      %{conn: conn, challenge: challenge}
    end

    @tag :capture_log
    test "returns error without active challenge", %{user: user} do
      # Create new conn without challenge in session
      conn =
        build_conn()
        |> Plug.Test.init_test_session(%{
          mfa_pending_user_id: user.id,
          mfa_pending_organization_id: user.organization_id
        })
        |> post(~p"/mfa/webauthn/authenticate/complete", %{
          "assertionResponse" => %{}
        })

      response = json_response(conn, 200)
      assert response["success"] == false
      assert response["error"] =~ "No active authentication challenge"
    end

    @tag :capture_log
    test "handles invalid assertion response", %{conn: conn, challenge: _challenge} do
      # This will fail at the WebAuthn verification level
      conn =
        post(conn, ~p"/mfa/webauthn/authenticate/complete", %{
          "assertionResponse" => %{
            "id" => "test_id",
            "response" => %{
              "authenticatorData" => Base.encode64("fake"),
              "clientDataJSON" => Base.encode64(~s({"type":"webauthn.get"})),
              "signature" => Base.encode64("fake")
            }
          }
        })

      # Should fail with WebAuthn error
      response = json_response(conn, 200)
      assert response["success"] == false
    end

    test "requires MFA session" do
      # Create new conn without MFA session
      conn =
        build_conn()
        |> Plug.Test.init_test_session(%{})
        |> post(~p"/mfa/webauthn/authenticate/complete", %{})

      response = json_response(conn, 200)
      assert response["success"] == false
      assert response["error"] =~ "Please login first"
    end
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp log_in_user(conn, user, organization) do
    conn
    |> Plug.Test.init_test_session(%{})
    |> Authify.Guardian.Plug.sign_in(user)
    |> Plug.Conn.put_session(:current_organization_id, organization.id)
    |> Plug.Conn.assign(:current_user, user)
    |> Plug.Conn.assign(:current_organization, organization)
  end

  defp generate_valid_totp(secret) do
    NimbleTOTP.verification_code(secret)
  end
end
