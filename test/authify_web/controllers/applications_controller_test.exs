defmodule AuthifyWeb.ApplicationsControllerTest do
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures
  import Authify.OAuthFixtures

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

  describe "index" do
    test "lists all applications", %{conn: conn, organization: organization} do
      conn = get(conn, ~p"/#{organization.slug}/applications")
      assert html_response(conn, 200) =~ "OAuth Applications"
    end
  end

  describe "new" do
    test "renders form", %{conn: conn, organization: organization} do
      conn = get(conn, ~p"/#{organization.slug}/applications/new")
      assert html_response(conn, 200) =~ "Create OAuth Application"
    end
  end

  describe "create" do
    test "redirects to show when data is valid", %{conn: conn, organization: organization} do
      create_attrs = %{
        name: "Test App",
        description: "A test application",
        redirect_uris: "https://example.com/callback",
        scopes: "openid profile email"
      }

      conn = post(conn, ~p"/#{organization.slug}/applications", application: create_attrs)

      assert %{id: id} = redirected_params(conn)
      assert redirected_to(conn) == ~p"/#{organization.slug}/applications/#{id}"

      conn = get(conn, ~p"/#{organization.slug}/applications/#{id}")
      assert html_response(conn, 200) =~ "Test App"
    end

    test "renders errors when data is invalid", %{conn: conn, organization: organization} do
      conn = post(conn, ~p"/#{organization.slug}/applications", application: %{})
      assert html_response(conn, 200) =~ "Create OAuth Application"
    end
  end

  describe "show" do
    setup [:create_application]

    test "displays application", %{
      conn: conn,
      application: application,
      organization: organization
    } do
      conn = get(conn, ~p"/#{organization.slug}/applications/#{application}")
      assert html_response(conn, 200) =~ application.name
    end
  end

  describe "edit" do
    setup [:create_application]

    test "renders form for editing chosen application", %{
      conn: conn,
      application: application,
      organization: organization
    } do
      conn = get(conn, ~p"/#{organization.slug}/applications/#{application}/edit")
      assert html_response(conn, 200) =~ "Edit #{application.name}"
    end
  end

  describe "update" do
    setup [:create_application]

    test "redirects when data is valid", %{
      conn: conn,
      application: application,
      organization: organization
    } do
      update_attrs = %{name: "Updated App", description: "Updated description"}

      conn =
        put(conn, ~p"/#{organization.slug}/applications/#{application}",
          application: update_attrs
        )

      assert redirected_to(conn) == ~p"/#{organization.slug}/applications/#{application}"

      conn = get(conn, ~p"/#{organization.slug}/applications/#{application}")
      assert html_response(conn, 200) =~ "Updated App"
    end

    test "renders errors when data is invalid", %{
      conn: conn,
      application: application,
      organization: organization
    } do
      conn =
        put(conn, ~p"/#{organization.slug}/applications/#{application}", application: %{name: ""})

      assert html_response(conn, 200) =~ "Edit #{application.name}"
    end
  end

  describe "delete" do
    setup [:create_application]

    test "deletes chosen application", %{
      conn: conn,
      application: application,
      organization: organization
    } do
      conn = delete(conn, ~p"/#{organization.slug}/applications/#{application}")
      assert redirected_to(conn) == ~p"/#{organization.slug}/applications"

      assert_error_sent 404, fn ->
        get(conn, ~p"/#{organization.slug}/applications/#{application}")
      end
    end
  end

  defp create_application(%{organization: organization}) do
    application = application_fixture(organization: organization)
    %{application: application}
  end
end
