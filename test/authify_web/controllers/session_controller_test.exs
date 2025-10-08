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
