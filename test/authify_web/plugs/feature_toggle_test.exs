defmodule AuthifyWeb.Plugs.FeatureToggleTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  alias Authify.Configurations
  alias AuthifyWeb.Plugs.FeatureToggle

  setup %{conn: conn} do
    organization = organization_fixture()

    conn = assign(conn, :current_organization, organization)

    {:ok, conn: conn, organization: organization}
  end

  @opts [feature: :allow_saml, message: "SAML is not enabled for this organization"]

  describe "call/2" do
    test "allows access when the feature is enabled (default)", %{conn: conn} do
      refute FeatureToggle.call(conn, @opts).halted
    end

    test "allows access when the feature is explicitly enabled", %{
      conn: conn,
      organization: organization
    } do
      Configurations.set_organization_setting(organization, :allow_saml, true)

      refute FeatureToggle.call(conn, @opts).halted
    end

    test "blocks access when the feature is disabled", %{
      conn: conn,
      organization: organization
    } do
      Configurations.set_organization_setting(organization, :allow_saml, false)

      conn = FeatureToggle.call(conn, @opts)

      assert conn.halted
      assert conn.status == 404
      assert response(conn, 404) =~ "SAML is not enabled"
    end

    test "blocks access when organization is not set", %{conn: conn} do
      conn =
        conn
        |> assign(:current_organization, nil)
        |> FeatureToggle.call(@opts)

      assert conn.halted
      assert conn.status == 404
    end
  end
end
