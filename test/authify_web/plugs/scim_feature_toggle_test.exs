defmodule AuthifyWeb.Plugs.ScimFeatureToggleTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  alias Authify.Configurations
  alias AuthifyWeb.Plugs.ScimFeatureToggle

  setup %{conn: conn} do
    organization = organization_fixture()

    conn =
      conn
      |> assign(:current_organization, organization)

    {:ok, conn: conn, organization: organization}
  end

  describe "ScimFeatureToggle plug" do
    test "allows access when SCIM is enabled (default)", %{conn: conn} do
      # SCIM is enabled by default
      conn = ScimFeatureToggle.call(conn, [])

      refute conn.halted
    end

    test "allows access when SCIM is explicitly enabled", %{
      conn: conn,
      organization: organization
    } do
      # Explicitly enable SCIM
      Configurations.set_organization_setting(
        organization,
        :scim_inbound_provisioning_enabled,
        true
      )

      conn = ScimFeatureToggle.call(conn, [])

      refute conn.halted
    end

    test "blocks access when SCIM is disabled", %{conn: conn, organization: organization} do
      # Disable SCIM
      Configurations.set_organization_setting(
        organization,
        :scim_inbound_provisioning_enabled,
        false
      )

      conn = ScimFeatureToggle.call(conn, [])

      assert conn.halted
      assert conn.status == 404
      assert get_resp_header(conn, "content-type") == ["application/scim+json; charset=utf-8"]

      response = json_response(conn, 404)
      assert response["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
      assert response["status"] == "404"
      assert response["detail"] =~ "SCIM provisioning is not enabled"
    end

    test "blocks access when organization is not set", %{conn: conn} do
      # Remove organization from conn
      conn = assign(conn, :current_organization, nil)

      conn = ScimFeatureToggle.call(conn, [])

      assert conn.halted
      assert conn.status == 404
    end
  end
end
