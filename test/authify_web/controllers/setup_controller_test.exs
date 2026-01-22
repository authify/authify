defmodule AuthifyWeb.SetupControllerTest do
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures
  alias Authify.Accounts

  describe "GET /setup" do
    test "shows setup form when no users exist", %{conn: conn} do
      # Ensure no users exist
      Authify.Repo.delete_all(Accounts.User)

      conn = get(conn, ~p"/setup")
      assert html_response(conn, 200) =~ "Initial System Setup"
      assert html_response(conn, 200) =~ "Create your global administrator account"
      assert html_response(conn, 200) =~ "Tenant Base Domain"
      assert html_response(conn, 200) =~ "First Name"
      assert html_response(conn, 200) =~ "Email Address"
    end

    test "redirects to login when users already exist", %{conn: conn} do
      # Create a user
      user_fixture()

      conn = get(conn, ~p"/setup")
      assert redirected_to(conn) == ~p"/login"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "System has already been set up"
    end
  end

  describe "POST /setup" do
    test "creates global admin user when no users exist", %{conn: conn} do
      # Ensure no users exist
      Authify.Repo.delete_all(Accounts.User)

      user_params = %{
        "first_name" => "Global",
        "last_name" => "Admin",
        "email" => "admin@example.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      conn =
        post(conn, ~p"/setup",
          user: user_params,
          tenant_base_domain: "authify.example.com"
        )

      assert redirected_to(conn) == ~p"/login?org_slug=authify-global"

      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~
               "Global admin account created successfully"

      # Verify user was created and is a global admin
      user =
        Accounts.get_user_by_email_and_organization(
          "admin@example.com",
          Accounts.get_global_organization!().id
        )

      assert user != nil
      assert Accounts.global_admin?(user)

      # Verify tenant_base_domain was set
      assert Authify.Configurations.get_global_setting(:tenant_base_domain) ==
               "authify.example.com"
    end

    test "shows errors for invalid user data", %{conn: conn} do
      # Ensure no users exist
      Authify.Repo.delete_all(Accounts.User)

      user_params = %{
        "first_name" => "",
        "email" => "not an email",
        "password" => "short",
        "password_confirmation" => "different"
      }

      conn =
        post(conn, ~p"/setup",
          user: user_params,
          tenant_base_domain: "authify.example.com"
        )

      # Should render the setup form again with validation errors
      assert html_response(conn, 200) =~ "Initial System Setup"
    end

    test "shows errors for missing tenant_base_domain", %{conn: conn} do
      # Ensure no users exist
      Authify.Repo.delete_all(Accounts.User)

      user_params = %{
        "first_name" => "Global",
        "last_name" => "Admin",
        "email" => "admin@example.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      conn = post(conn, ~p"/setup", user: user_params)

      assert html_response(conn, 200) =~ "Initial System Setup"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Tenant base domain is required"
    end

    test "shows errors for invalid tenant_base_domain", %{conn: conn} do
      # Ensure no users exist
      Authify.Repo.delete_all(Accounts.User)

      user_params = %{
        "first_name" => "Global",
        "last_name" => "Admin",
        "email" => "admin@example.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      conn =
        post(conn, ~p"/setup",
          user: user_params,
          tenant_base_domain: "not a domain!"
        )

      assert html_response(conn, 200) =~ "Initial System Setup"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "must be a valid domain name"
    end

    test "creates admin and configures authify_domain when provided", %{conn: conn} do
      # Ensure no users exist
      Authify.Repo.delete_all(Accounts.User)

      user_params = %{
        "first_name" => "Global",
        "last_name" => "Admin",
        "email" => "admin@example.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      conn =
        post(conn, ~p"/setup",
          user: user_params,
          tenant_base_domain: "authify.example.com",
          authify_domain: "admin.example.com"
        )

      assert redirected_to(conn) == ~p"/login?org_slug=authify-global"

      # Verify authify_domain was configured
      global_org = Authify.Accounts.get_global_organization()

      # Check that CNAME was created
      cnames = Authify.Organizations.list_organization_cnames(global_org)
      assert length(cnames) == 1
      assert hd(cnames).domain == "admin.example.com"

      # Check that email_link_domain was set (global setting)
      assert Authify.Configurations.get_global_setting(:email_link_domain) ==
               "admin.example.com"
    end

    test "works without authify_domain (optional)", %{conn: conn} do
      # Ensure no users exist
      Authify.Repo.delete_all(Accounts.User)
      # Clear cache to avoid pollution from previous tests
      Authify.Configurations.Cache.clear()

      user_params = %{
        "first_name" => "Global",
        "last_name" => "Admin",
        "email" => "admin@example.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      conn =
        post(conn, ~p"/setup",
          user: user_params,
          tenant_base_domain: "authify.example.com"
        )

      assert redirected_to(conn) == ~p"/login?org_slug=authify-global"

      # Verify no CNAME was created
      global_org = Authify.Accounts.get_global_organization()
      cnames = Authify.Organizations.list_organization_cnames(global_org)
      assert Enum.empty?(cnames)

      # email_link_domain should be default (not explicitly set, so nil)
      assert Authify.Configurations.get_global_setting(:email_link_domain) == nil
    end

    test "redirects to login when users already exist", %{conn: conn} do
      # Create a user
      user_fixture()

      user_params = %{
        "first_name" => "Test",
        "last_name" => "User",
        "email" => "test@example.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      conn =
        post(conn, ~p"/setup",
          user: user_params,
          tenant_base_domain: "authify.example.com"
        )

      assert redirected_to(conn) == ~p"/login"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "System has already been set up"
    end
  end
end
