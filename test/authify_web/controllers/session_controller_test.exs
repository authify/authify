defmodule AuthifyWeb.SessionControllerTest do
  use AuthifyWeb.ConnCase

  alias Authify.Accounts

  describe "GET /login" do
    test "displays login form", %{conn: conn} do
      conn = get(conn, ~p"/login")
      assert html_response(conn, 200) =~ "Sign In"
      assert html_response(conn, 200) =~ "Organization"
      assert html_response(conn, 200) =~ "Email Address"
      assert html_response(conn, 200) =~ "Password"
    end
  end

  describe "POST /login" do
    test "logs in user with valid credentials", %{conn: conn} do
      # Create organization and user
      {:ok, organization} = Accounts.create_organization(%{name: "Test Org", slug: "test-org"})

      user_attrs = %{
        "first_name" => "John",
        "last_name" => "Doe",
        "email" => "john@test.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      {:ok, _user} = Accounts.create_user_with_role(user_attrs, organization.id, "user")

      login_params = %{
        "organization_slug" => "test-org",
        "email" => "john@test.com",
        "password" => "SecureP@ssw0rd!"
      }

      conn = post(conn, ~p"/login", login: login_params)

      assert redirected_to(conn) == ~p"/#{organization.slug}/user/dashboard"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "Welcome back!"
    end

    test "shows error with invalid organization", %{conn: conn} do
      login_params = %{
        "organization_slug" => "nonexistent",
        "email" => "john@test.com",
        "password" => "SecureP@ssw0rd!"
      }

      conn = post(conn, ~p"/login", login: login_params)

      assert html_response(conn, 200) =~ "Sign In"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Organization not found"
    end

    test "shows error with invalid credentials", %{conn: conn} do
      # Create organization
      {:ok, organization} = Accounts.create_organization(%{name: "Test Org", slug: "test-org"})

      user_attrs = %{
        "first_name" => "John",
        "last_name" => "Doe",
        "email" => "john@test.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      {:ok, _user} = Accounts.create_user_with_role(user_attrs, organization.id, "user")

      login_params = %{
        "organization_slug" => "test-org",
        "email" => "john@test.com",
        "password" => "wrong_password"
      }

      conn = post(conn, ~p"/login", login: login_params)

      assert html_response(conn, 200) =~ "Sign In"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Invalid email or password"
    end

    test "shows error with non-existent user", %{conn: conn} do
      # Create organization but no user
      {:ok, _organization} = Accounts.create_organization(%{name: "Test Org", slug: "test-org"})

      login_params = %{
        "organization_slug" => "test-org",
        "email" => "nonexistent@test.com",
        "password" => "SecureP@ssw0rd!"
      }

      conn = post(conn, ~p"/login", login: login_params)

      assert html_response(conn, 200) =~ "Sign In"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Invalid email or password"
    end

    test "redirects to MFA verification when TOTP is enabled", %{conn: conn} do
      # Create organization and user
      {:ok, organization} = Accounts.create_organization(%{name: "Test Org", slug: "test-org"})

      user_attrs = %{
        "first_name" => "John",
        "last_name" => "Doe",
        "email" => "john@test.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      {:ok, user} = Accounts.create_user_with_role(user_attrs, organization.id, "user")

      # Enable TOTP for user
      {:ok, secret} = Authify.MFA.setup_totp(user)
      code = NimbleTOTP.verification_code(secret)
      {:ok, _user, _codes} = Authify.MFA.complete_totp_setup(user, code, secret)

      login_params = %{
        "organization_slug" => "test-org",
        "email" => "john@test.com",
        "password" => "SecureP@ssw0rd!"
      }

      conn = post(conn, ~p"/login", login: login_params)

      # Should redirect to MFA verification
      assert redirected_to(conn) == ~p"/mfa/verify"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "authentication code"

      # Verify session contains MFA pending info
      assert get_session(conn, :mfa_pending_user_id) == user.id
      assert get_session(conn, :mfa_pending_organization_id) == organization.id
    end

    test "completes login when TOTP is enabled but trusted device exists", %{conn: conn} do
      # Create organization and user
      {:ok, organization} = Accounts.create_organization(%{name: "Test Org", slug: "test-org"})

      user_attrs = %{
        "first_name" => "John",
        "last_name" => "Doe",
        "email" => "john@test.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      {:ok, user} = Accounts.create_user_with_role(user_attrs, organization.id, "user")

      # Enable TOTP for user
      {:ok, secret} = Authify.MFA.setup_totp(user)
      code = NimbleTOTP.verification_code(secret)
      {:ok, user, _codes} = Authify.MFA.complete_totp_setup(user, code, secret)

      # Create trusted device
      {:ok, _device, plaintext_token} =
        Authify.MFA.create_trusted_device(user, %{
          device_name: "Test Device",
          ip_address: "127.0.0.1",
          user_agent: "Test User Agent"
        })

      login_params = %{
        "organization_slug" => "test-org",
        "email" => "john@test.com",
        "password" => "SecureP@ssw0rd!"
      }

      # Set trusted device token in session
      conn =
        conn
        |> Plug.Test.init_test_session(%{mfa_trusted_device_token: plaintext_token})
        |> post(~p"/login", login: login_params)

      # Should complete login and skip MFA verification
      assert redirected_to(conn) == ~p"/#{organization.slug}/user/dashboard"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "Welcome back!"
    end
  end

  describe "DELETE /logout" do
    test "logs out the user", %{conn: conn} do
      # Create organization and user
      {:ok, organization} = Accounts.create_organization(%{name: "Test Org", slug: "test-org"})

      user_attrs = %{
        "first_name" => "John",
        "last_name" => "Doe",
        "email" => "john@test.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      {:ok, user} = Accounts.create_user_with_role(user_attrs, organization.id, "user")

      # Log in the user first
      conn = Authify.Guardian.Plug.sign_in(conn, user)

      # Now log out
      conn = delete(conn, ~p"/logout")

      assert redirected_to(conn) == ~p"/"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "logged out"
    end
  end
end
