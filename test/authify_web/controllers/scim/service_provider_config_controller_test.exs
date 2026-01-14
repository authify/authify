defmodule AuthifyWeb.SCIM.ServiceProviderConfigControllerTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  setup %{conn: conn} do
    organization = organization_fixture()
    admin_user = user_fixture(organization: organization, role: "admin")

    conn =
      conn
      |> assign(:current_organization, organization)
      |> assign(:current_user, admin_user)
      |> assign(:api_authenticated, true)
      |> assign(:current_scopes, ["scim:read"])

    {:ok, conn: conn, organization: organization}
  end

  describe "GET /scim/v2/ServiceProviderConfig" do
    test "returns service provider configuration", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/scim/v2/ServiceProviderConfig")

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == ["application/scim+json; charset=utf-8"]

      response = json_response(conn, 200)

      # Verify schema
      assert response["schemas"] == [
               "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
             ]

      # Verify patch support
      assert response["patch"]["supported"] == true

      # Verify bulk not supported
      assert response["bulk"]["supported"] == false
      assert response["bulk"]["maxOperations"] == 0

      # Verify filter support
      assert response["filter"]["supported"] == true
      assert response["filter"]["maxResults"] == 100

      # Verify changePassword not supported
      assert response["changePassword"]["supported"] == false

      # Verify sort support
      assert response["sort"]["supported"] == true

      # Verify etag not supported
      assert response["etag"]["supported"] == false

      # Verify authentication schemes
      assert [auth_scheme] = response["authenticationSchemes"]
      assert auth_scheme["type"] == "oauthbearertoken"
      assert auth_scheme["name"] == "OAuth 2.0 Bearer Token"
      assert auth_scheme["primary"] == true

      # Verify meta
      assert response["meta"]["resourceType"] == "ServiceProviderConfig"

      assert response["meta"]["location"] ==
               "http://localhost:4002/#{organization.slug}/scim/v2/ServiceProviderConfig"

      # Verify documentation URI
      assert String.contains?(response["documentationUri"], "scim-integration-guide")
    end
  end
end
