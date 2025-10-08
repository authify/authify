defmodule AuthifyWeb.Auth.APIScopeTest do
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures
  import Authify.OAuthFixtures

  describe "scope validation" do
    setup do
      organization = organization_fixture()

      application =
        management_api_application_fixture(
          organization: organization,
          scopes: "management_app:read users:write saml:read"
        )

      %{
        organization: organization,
        application: application
      }
    end

    test "allows access with sufficient scopes", %{
      conn: conn,
      application: application,
      organization: organization
    } do
      # Get access token with multiple scopes
      {:ok, access_token} =
        Authify.OAuth.create_management_api_access_token(
          application,
          "management_app:read users:write"
        )

      # Test APIAuth with required scopes (set organization first like the pipeline does)
      conn =
        conn
        |> assign(:current_organization, organization)
        |> put_req_header("authorization", "Bearer #{access_token.token}")
        |> AuthifyWeb.Auth.APIAuth.call(require_scopes: ["management_app:read"])

      assert conn.assigns.current_scopes == ["management_app:read", "users:write"]
      refute conn.halted
    end

    test "denies access with insufficient scopes", %{
      conn: conn,
      application: application,
      organization: organization
    } do
      # Get access token with limited scopes
      {:ok, access_token} =
        Authify.OAuth.create_management_api_access_token(application, "users:read")

      # Test APIAuth with required scopes that aren't present
      conn =
        conn
        |> assign(:current_organization, organization)
        |> put_req_header("authorization", "Bearer #{access_token.token}")
        |> AuthifyWeb.Auth.APIAuth.call(require_scopes: ["saml:read"])

      assert conn.status == 403
      assert conn.halted

      response = json_response(conn, 403)
      assert response["error"]["type"] == "insufficient_scope"
      assert "saml:read" in response["error"]["details"]["required"]
      assert "users:read" in response["error"]["details"]["provided"]
    end

    test "write scope includes read access", %{
      conn: conn,
      application: application,
      organization: organization
    } do
      # Get access token with write scope
      {:ok, access_token} =
        Authify.OAuth.create_management_api_access_token(application, "users:write")

      # Test that write scope satisfies read requirement
      conn =
        conn
        |> assign(:current_organization, organization)
        |> put_req_header("authorization", "Bearer #{access_token.token}")
        |> AuthifyWeb.Auth.APIAuth.call(require_scopes: ["users:read"])

      assert conn.assigns.current_scopes == ["users:write"]
      refute conn.halted
    end

    test "management_app:write does not grant other write scopes", %{
      conn: conn,
      application: application,
      organization: organization
    } do
      # Get access token with management_app:write scope only
      {:ok, access_token} =
        Authify.OAuth.create_management_api_access_token(application, "management_app:write")

      # Test that management_app:write does NOT satisfy users:write requirements
      conn =
        conn
        |> assign(:current_organization, organization)
        |> put_req_header("authorization", "Bearer #{access_token.token}")
        |> AuthifyWeb.Auth.APIAuth.call(require_scopes: ["users:write"])

      assert conn.status == 403
      assert conn.halted
    end

    test "management_app:read does not grant other read scopes", %{
      conn: conn,
      application: application,
      organization: organization
    } do
      # Get access token with management_app:read scope only
      {:ok, access_token} =
        Authify.OAuth.create_management_api_access_token(application, "management_app:read")

      # Test that management_app:read does NOT satisfy users:read requirements
      conn =
        conn
        |> assign(:current_organization, organization)
        |> put_req_header("authorization", "Bearer #{access_token.token}")
        |> AuthifyWeb.Auth.APIAuth.call(require_scopes: ["users:read"])

      assert conn.status == 403
      assert conn.halted
    end

    test "no scope requirements allows all authenticated users", %{
      conn: conn,
      application: application,
      organization: organization
    } do
      # Get access token with any scope
      {:ok, access_token} =
        Authify.OAuth.create_management_api_access_token(application, "users:read")

      # Test APIAuth without scope requirements
      conn =
        conn
        |> assign(:current_organization, organization)
        |> put_req_header("authorization", "Bearer #{access_token.token}")
        |> AuthifyWeb.Auth.APIAuth.call([])

      assert conn.assigns.current_scopes == ["users:read"]
      refute conn.halted
    end
  end
end
