defmodule AuthifyWeb.Auth.OrganizationContextTest do
  use AuthifyWeb.ConnCase

  alias Authify.Accounts
  alias AuthifyWeb.Auth.OrganizationContext

  describe "organization context middleware" do
    setup do
      # Create organization and user
      {:ok, organization} = Accounts.create_organization(%{name: "Test Org", slug: "test-org"})

      user_attrs = %{
        "first_name" => "Test",
        "last_name" => "User",
        "email" => "test@example.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      {:ok, user} = Accounts.create_user_with_role(user_attrs, organization.id, "user")

      %{organization: organization, user: user}
    end

    test "adds current_user and current_organization to assigns for authenticated user", %{
      conn: conn,
      user: user,
      organization: organization
    } do
      conn =
        conn
        |> Plug.Test.init_test_session(%{})
        |> Authify.Guardian.Plug.sign_in(user)
        |> OrganizationContext.call([])

      assert conn.assigns.current_user.id == user.id
      assert conn.assigns.current_organization.id == organization.id
      assert conn.assigns.current_organization.name == organization.name
    end

    test "does not add assigns for unauthenticated user", %{conn: conn} do
      conn = OrganizationContext.call(conn, [])

      refute Map.has_key?(conn.assigns, :current_user)
      refute Map.has_key?(conn.assigns, :current_organization)
    end
  end

  describe "require_organization_resource/2" do
    setup do
      # Create two organizations
      {:ok, org1} = Accounts.create_organization(%{name: "Org 1", slug: "org-1"})
      {:ok, org2} = Accounts.create_organization(%{name: "Org 2", slug: "org-2"})

      user_attrs = %{
        "first_name" => "Test",
        "last_name" => "User",
        "email" => "test@example.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      {:ok, user} = Accounts.create_user_with_role(user_attrs, org1.id, "user")

      %{org1: org1, org2: org2, user: user}
    end

    test "allows access to user's own organization resources", %{
      conn: conn,
      user: user,
      org1: org1
    } do
      conn =
        conn
        |> Plug.Test.init_test_session(%{})
        |> Authify.Guardian.Plug.sign_in(user)
        |> OrganizationContext.call([])
        |> OrganizationContext.require_organization_resource(org1.id)

      refute conn.halted
    end

    test "denies access to other organization resources", %{
      conn: conn,
      user: user,
      org2: org2
    } do
      conn =
        conn
        |> bypass_through(AuthifyWeb.Router, :browser)
        |> get("/")
        |> fetch_session()
        |> Authify.Guardian.Plug.sign_in(user)
        |> OrganizationContext.call([])
        |> OrganizationContext.require_organization_resource(org2.id)

      assert conn.halted
      assert conn.status == 404
    end
  end

  describe "require_admin/2" do
    setup do
      {:ok, organization} = Accounts.create_organization(%{name: "Test Org", slug: "test-org"})

      admin_attrs = %{
        "first_name" => "Admin",
        "last_name" => "User",
        "email" => "admin@example.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      user_attrs = %{
        "first_name" => "Regular",
        "last_name" => "User",
        "email" => "user@example.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      {:ok, admin} = Accounts.create_user_with_role(admin_attrs, organization.id, "admin")
      {:ok, user} = Accounts.create_user_with_role(user_attrs, organization.id, "user")

      %{organization: organization, admin: admin, user: user}
    end

    test "allows access for admin users", %{conn: conn, admin: admin} do
      conn =
        conn
        |> bypass_through(AuthifyWeb.Router, :browser)
        |> get("/")
        |> Authify.Guardian.Plug.sign_in(admin)
        |> OrganizationContext.call([])
        |> OrganizationContext.require_admin([])

      refute conn.halted
    end

    test "denies access for regular users", %{conn: conn, user: user, organization: organization} do
      conn =
        conn
        |> bypass_through(AuthifyWeb.Router, :browser)
        |> get("/")
        |> Authify.Guardian.Plug.sign_in(user)
        |> OrganizationContext.call([])
        |> OrganizationContext.require_admin([])

      assert conn.halted
      assert conn.status == 302
      assert redirected_to(conn) == "/#{organization.slug}/dashboard"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Access denied"
    end
  end
end
