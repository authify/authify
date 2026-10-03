defmodule AuthifyWeb.Plugs.WebAuthnFeatureToggleTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  alias Authify.Configurations
  alias AuthifyWeb.Plugs.WebAuthnFeatureToggle

  setup %{conn: conn} do
    organization = organization_fixture()

    conn = assign(conn, :current_organization, organization)

    {:ok, conn: conn, organization: organization}
  end

  describe "call/2" do
    test "allows access when WebAuthn is enabled (default)", %{conn: conn} do
      conn = WebAuthnFeatureToggle.call(conn, [])

      refute conn.halted
    end

    test "allows access when WebAuthn is explicitly enabled", %{
      conn: conn,
      organization: organization
    } do
      Configurations.set_organization_setting(organization, :allow_webauthn, true)

      conn = WebAuthnFeatureToggle.call(conn, [])

      refute conn.halted
    end

    test "blocks access when WebAuthn is disabled", %{conn: conn, organization: organization} do
      Configurations.set_organization_setting(organization, :allow_webauthn, false)

      conn = WebAuthnFeatureToggle.call(conn, [])

      assert conn.halted
      assert conn.status == 404
      assert response(conn, 404) =~ "WebAuthn is not enabled"
    end

    test "blocks access when organization is not set", %{conn: conn} do
      conn =
        conn
        |> assign(:current_organization, nil)
        |> WebAuthnFeatureToggle.call([])

      assert conn.halted
      assert conn.status == 404
    end
  end
end
