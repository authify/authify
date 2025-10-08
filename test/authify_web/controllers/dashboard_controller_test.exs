defmodule AuthifyWeb.DashboardControllerTest do
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures

  alias Authify.Accounts

  describe "GET /dashboard" do
    setup do
      # Create organization and admin user
      {:ok, organization} = Accounts.create_organization(%{name: "Test Org", slug: "test-org"})

      admin_attrs = %{
        "first_name" => "Admin",
        "last_name" => "User",
        "username" => "admin",
        "email" => "admin@test.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      {:ok, admin} = Accounts.create_user_with_role(admin_attrs, organization.id, "admin")

      %{organization: organization, admin: admin}
    end

    test "displays dashboard for authenticated user", %{
      conn: conn,
      admin: admin,
      organization: organization
    } do
      conn = Authify.Guardian.Plug.sign_in(conn, admin)
      conn = get(conn, ~p"/#{organization.slug}/dashboard")

      assert html_response(conn, 200) =~ "Dashboard"
      assert html_response(conn, 200) =~ organization.name
      assert html_response(conn, 200) =~ organization.slug
      assert html_response(conn, 200) =~ "Total Users"
      assert html_response(conn, 200) =~ "Applications"
      assert html_response(conn, 200) =~ "Active Sessions"
      assert html_response(conn, 200) =~ "Recent Users"
    end

    test "redirects unauthenticated user to login", %{conn: conn} do
      organization = organization_fixture()
      conn = get(conn, ~p"/#{organization.slug}/dashboard")
      assert redirected_to(conn) == "/login"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Authentication required"
    end

    test "shows user count in stats", %{conn: conn, admin: admin, organization: organization} do
      # Create additional user
      user_attrs = %{
        "first_name" => "Regular",
        "last_name" => "User",
        "username" => "user",
        "email" => "user@test.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      {:ok, _user} = Accounts.create_user_with_role(user_attrs, organization.id, "user")

      conn = Authify.Guardian.Plug.sign_in(conn, admin)
      conn = get(conn, ~p"/#{organization.slug}/dashboard")

      # Should show 2 users (admin + regular user)
      assert html_response(conn, 200) =~ ">2<"
    end

    test "shows user details in recent users table", %{
      conn: conn,
      admin: admin,
      organization: organization
    } do
      conn = Authify.Guardian.Plug.sign_in(conn, admin)
      conn = get(conn, ~p"/#{organization.slug}/dashboard")

      assert html_response(conn, 200) =~ "Admin User"
      assert html_response(conn, 200) =~ "admin@test.com"
      assert html_response(conn, 200) =~ "Admin"
    end

    test "shows correct user information in sidebar", %{
      conn: conn,
      admin: admin,
      organization: organization
    } do
      conn = Authify.Guardian.Plug.sign_in(conn, admin)
      conn = get(conn, ~p"/#{organization.slug}/dashboard")

      assert html_response(conn, 200) =~ "Signed in as"
      assert html_response(conn, 200) =~ "Admin User"
      assert html_response(conn, 200) =~ "admin@test.com"
    end
  end

  describe "GET /dashboard - Global Admin" do
    setup do
      # Create or get the global organization
      global_org =
        Accounts.get_organization_by_slug("authify-global") ||
          elem(Accounts.create_organization(%{name: "Global", slug: "authify-global"}), 1)

      global_admin_attrs = %{
        "first_name" => "Global",
        "last_name" => "Admin",
        "username" => "globaladmin",
        "email" => "globaladmin@test.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      {:ok, global_admin} =
        Accounts.create_user_with_role(global_admin_attrs, global_org.id, "admin")

      %{global_organization: global_org, global_admin: global_admin}
    end

    test "displays global admin dashboard without errors", %{
      conn: conn,
      global_admin: global_admin,
      global_organization: global_org
    } do
      conn =
        conn
        |> Plug.Test.init_test_session(%{})
        |> Authify.Guardian.Plug.sign_in(global_admin)
        |> put_session(:current_organization_id, global_org.id)
        |> assign(:current_organization, global_org)
        |> assign(:current_user, global_admin)

      conn = get(conn, ~p"/#{global_org.slug}/dashboard")

      assert html_response(conn, 200) =~ "Global Administration Dashboard"
      assert html_response(conn, 200) =~ "Total Organizations"
      assert html_response(conn, 200) =~ "Total Users"
      assert html_response(conn, 200) =~ "Global Admins"
      assert html_response(conn, 200) =~ "System Status"
    end

    test "displays system statistics correctly", %{
      conn: conn,
      global_admin: global_admin,
      global_organization: global_org
    } do
      conn =
        conn
        |> Plug.Test.init_test_session(%{})
        |> Authify.Guardian.Plug.sign_in(global_admin)
        |> put_session(:current_organization_id, global_org.id)
        |> assign(:current_organization, global_org)
        |> assign(:current_user, global_admin)

      conn = get(conn, ~p"/#{global_org.slug}/dashboard")

      # Should show the system stats without errors
      response = html_response(conn, 200)
      assert response =~ "Organization Management"
      assert response =~ "User Management"
      assert response =~ "System Maintenance"
      assert response =~ "System Invitation Statistics"
    end

    test "displays invitation statistics without errors", %{
      conn: conn,
      global_admin: global_admin,
      global_organization: global_org
    } do
      conn =
        conn
        |> Plug.Test.init_test_session(%{})
        |> Authify.Guardian.Plug.sign_in(global_admin)
        |> put_session(:current_organization_id, global_org.id)
        |> assign(:current_organization, global_org)
        |> assign(:current_user, global_admin)

      conn = get(conn, ~p"/#{global_org.slug}/dashboard")

      # Should display invitation stats without template errors
      response = html_response(conn, 200)
      assert response =~ "Total Invitations"
      assert response =~ "Accepted"
      assert response =~ "Pending"
      assert response =~ "Acceptance Rate"
    end
  end
end
