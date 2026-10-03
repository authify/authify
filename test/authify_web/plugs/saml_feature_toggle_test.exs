defmodule AuthifyWeb.Plugs.SamlFeatureToggleTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  alias Authify.Configurations
  alias AuthifyWeb.Plugs.SamlFeatureToggle

  setup %{conn: conn} do
    organization = organization_fixture()

    conn = assign(conn, :current_organization, organization)

    {:ok, conn: conn, organization: organization}
  end

  describe "call/2" do
    test "allows access when SAML is enabled (default)", %{conn: conn} do
      conn = SamlFeatureToggle.call(conn, [])

      refute conn.halted
    end

    test "allows access when SAML is explicitly enabled", %{
      conn: conn,
      organization: organization
    } do
      Configurations.set_organization_setting(organization, :allow_saml, true)

      conn = SamlFeatureToggle.call(conn, [])

      refute conn.halted
    end

    test "blocks access when SAML is disabled", %{conn: conn, organization: organization} do
      Configurations.set_organization_setting(organization, :allow_saml, false)

      conn = SamlFeatureToggle.call(conn, [])

      assert conn.halted
      assert conn.status == 404
      assert response(conn, 404) =~ "SAML is not enabled"
    end

    test "blocks access when organization is not set", %{conn: conn} do
      conn =
        conn
        |> assign(:current_organization, nil)
        |> SamlFeatureToggle.call([])

      assert conn.halted
      assert conn.status == 404
    end
  end
end
