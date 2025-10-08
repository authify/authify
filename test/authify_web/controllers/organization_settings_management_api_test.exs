defmodule AuthifyWeb.OrganizationSettingsManagementApiTest do
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures
  import Authify.OAuthFixtures

  alias Authify.OAuth.Application

  describe "management_api" do
    setup do
      organization = organization_fixture()
      admin_user = user_fixture(organization: organization, role: "admin")
      regular_user = user_fixture(organization: organization, role: "user")
      %{organization: organization, admin_user: admin_user, regular_user: regular_user}
    end

    test "shows management API page with no applications", %{
      conn: conn,
      admin_user: admin_user,
      organization: organization
    } do
      conn = log_in_user(conn, admin_user)
      conn = get(conn, ~p"/#{organization.slug}/settings/management-api")

      assert html_response(conn, 200) =~ "No Management API Applications"
      assert html_response(conn, 200) =~ "Create Your First API Application"
    end

    test "shows management API applications when they exist", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      # Create a management API application
      management_api_application_fixture(
        organization: organization,
        name: "Test API App",
        scopes: "management_app:read users:write"
      )

      conn = log_in_user(conn, admin_user)
      conn = get(conn, ~p"/#{organization.slug}/settings/management-api")

      assert html_response(conn, 200) =~ "Test API App"
      assert html_response(conn, 200) =~ "management_app:read"
      assert html_response(conn, 200) =~ "users:write"
    end

    test "creates management API application with scopes", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      conn = log_in_user(conn, admin_user)

      conn =
        post(conn, ~p"/#{organization.slug}/settings/management-api", %{
          "application" => %{
            "name" => "New API App",
            "description" => "Test description"
          },
          "scopes" => ["management_app:read", "users:write"]
        })

      assert redirected_to(conn) == ~p"/#{organization.slug}/settings/management-api"

      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~
               "Management API application created successfully"

      # Verify the application was created
      app =
        Authify.OAuth.list_applications(organization)
        |> Enum.find(&(&1.name == "New API App"))

      assert app.application_type == "management_api_app"
      assert Application.scopes_list(app) == ["management_app:read", "users:write"]
      assert app.redirect_uris == ""
    end

    test "creates management API application without scopes", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      conn = log_in_user(conn, admin_user)

      conn =
        post(conn, ~p"/#{organization.slug}/settings/management-api", %{
          "application" => %{
            "name" => "No Scopes App",
            "description" => "Test description"
          }
        })

      assert redirected_to(conn) == ~p"/#{organization.slug}/settings/management-api"

      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~
               "Management API application created successfully"

      # Verify the application was created
      app =
        Authify.OAuth.list_applications(organization)
        |> Enum.find(&(&1.name == "No Scopes App"))

      assert app.application_type == "management_api_app"
      assert Application.scopes_list(app) == []
    end

    test "regular users cannot access management API page", %{
      conn: conn,
      regular_user: regular_user,
      organization: organization
    } do
      conn = log_in_user(conn, regular_user)
      conn = get(conn, ~p"/#{organization.slug}/settings/management-api")

      assert redirected_to(conn) == "/#{organization.slug}/dashboard"

      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~
               "Access denied. Admin privileges required."
    end

    test "regular users cannot create management API applications", %{
      conn: conn,
      regular_user: regular_user,
      organization: organization
    } do
      conn = log_in_user(conn, regular_user)

      conn =
        post(conn, ~p"/#{organization.slug}/settings/management-api", %{
          "application" => %{
            "name" => "Unauthorized App",
            "description" => "Should not be created"
          },
          "scopes" => ["management_app:read"]
        })

      assert redirected_to(conn) == "/#{organization.slug}/dashboard"

      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~
               "Access denied. Admin privileges required."
    end

    test "admin can create management API application with invitation scopes", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      conn = log_in_user(conn, admin_user)

      conn =
        post(conn, ~p"/#{organization.slug}/settings/management-api", %{
          "application" => %{
            "name" => "Invitations API App",
            "description" => "App for managing invitations"
          },
          "scopes" => ["invitations:read", "invitations:write", "users:read"]
        })

      assert redirected_to(conn) == ~p"/#{organization.slug}/settings/management-api"

      # Should be successful now that we've added the scopes to the validation
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~
               "Management API application created successfully"

      # Verify the application was created with correct scopes
      app =
        Authify.OAuth.list_applications(organization)
        |> Enum.find(&(&1.name == "Invitations API App"))

      assert app.application_type == "management_api_app"

      assert Application.scopes_list(app) == [
               "invitations:read",
               "invitations:write",
               "users:read"
             ]

      # Verify scopes can be parsed correctly
      scopes_list = Application.scopes_list(app)
      assert "invitations:read" in scopes_list
      assert "invitations:write" in scopes_list
      assert "users:read" in scopes_list
    end
  end
end
