defmodule AuthifyWeb.OrganizationSettingsControllerTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  setup %{conn: conn} do
    organization = organization_fixture()
    admin_user = user_fixture(organization: organization, role: "admin")
    regular_user = user_fixture(organization: organization, role: "user")

    conn =
      conn
      |> log_in_user(admin_user)
      |> assign(:current_user, admin_user)
      |> assign(:current_organization, organization)

    %{conn: conn, admin_user: admin_user, regular_user: regular_user, organization: organization}
  end

  describe "show/2" do
    test "renders organization settings page", %{conn: conn, organization: organization} do
      conn = get(conn, ~p"/#{organization.slug}/settings")
      assert html_response(conn, 200) =~ "Organization Settings"
      assert html_response(conn, 200) =~ organization.name
    end
  end

  describe "access control" do
    test "regular users cannot access organization settings", %{
      regular_user: regular_user,
      organization: organization
    } do
      conn =
        build_conn()
        |> log_in_user(regular_user)
        |> assign(:current_user, regular_user)
        |> assign(:current_organization, organization)

      conn = get(conn, ~p"/#{organization.slug}/settings")

      assert redirected_to(conn) == "/#{organization.slug}/dashboard"

      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~
               "Access denied. Admin privileges required."
    end
  end
end
