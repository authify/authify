defmodule AuthifyWeb.Plugs.OAuthFeatureToggleTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  alias Authify.Configurations
  alias AuthifyWeb.Plugs.OAuthFeatureToggle

  setup %{conn: conn} do
    organization = organization_fixture()

    conn = assign(conn, :current_organization, organization)

    {:ok, conn: conn, organization: organization}
  end

  describe "call/2" do
    test "allows access when OAuth is enabled (default)", %{conn: conn} do
      conn = OAuthFeatureToggle.call(conn, [])

      refute conn.halted
    end

    test "allows access when OAuth is explicitly enabled", %{
      conn: conn,
      organization: organization
    } do
      Configurations.set_organization_setting(organization, :allow_oauth, true)

      conn = OAuthFeatureToggle.call(conn, [])

      refute conn.halted
    end

    test "blocks access when OAuth is disabled", %{conn: conn, organization: organization} do
      Configurations.set_organization_setting(organization, :allow_oauth, false)

      conn = OAuthFeatureToggle.call(conn, [])

      assert conn.halted
      assert conn.status == 404
      assert response(conn, 404) =~ "OAuth2/OIDC is not enabled"
    end

    test "blocks access when organization is not set", %{conn: conn} do
      conn =
        conn
        |> assign(:current_organization, nil)
        |> OAuthFeatureToggle.call([])

      assert conn.halted
      assert conn.status == 404
    end
  end
end
