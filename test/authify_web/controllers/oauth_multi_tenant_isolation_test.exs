defmodule AuthifyWeb.OAuthMultiTenantIsolationTest do
  @moduledoc """
  Integration tests to verify strict multi-tenant isolation for OAuth2/OIDC flows.

  These tests ensure that:
  - OAuth applications from one organization cannot access resources from another
  - Authorization codes and tokens are properly scoped to organizations
  - Users can only authorize applications within their own organization
  - Cross-tenant access attempts are properly rejected
  """
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures
  import Authify.OAuthFixtures

  alias Authify.Accounts.User

  describe "OAuth application isolation" do
    setup do
      # Create two separate organizations with users and apps
      org_a = organization_fixture(%{name: "Organization A", slug: "org-a"})
      org_b = organization_fixture(%{name: "Organization B", slug: "org-b"})

      user_a = user_for_organization_fixture(org_a)
      user_b = user_for_organization_fixture(org_b)

      app_a = application_fixture(organization: org_a)
      app_b = application_fixture(organization: org_b)

      %{
        org_a: org_a,
        org_b: org_b,
        user_a: user_a,
        user_b: user_b,
        app_a: app_a,
        app_b: app_b
      }
    end

    test "user from org A cannot authorize app from org B", %{
      conn: conn,
      user_a: user_a,
      app_b: app_b,
      org_a: org_a
    } do
      conn = log_in_user(conn, user_a)

      # Try to authorize org B's app through org A's endpoint
      params = %{
        "client_id" => app_b.client_id,
        "redirect_uri" => "https://example.com/callback",
        "response_type" => "code",
        "scope" => "openid profile"
      }

      conn = get(conn, ~p"/#{org_a.slug}/oauth/authorize", params)

      # Should redirect with error - app not found in this org
      assert redirected_to(conn) =~ "https://example.com/callback"
      assert redirected_to(conn) =~ "error=invalid_client"
    end

    test "user from org B cannot authorize app from org A", %{
      conn: conn,
      user_b: user_b,
      app_a: app_a,
      org_b: org_b
    } do
      conn = log_in_user(conn, user_b)

      params = %{
        "client_id" => app_a.client_id,
        "redirect_uri" => "https://example.com/callback",
        "response_type" => "code",
        "scope" => "openid profile"
      }

      conn = get(conn, ~p"/#{org_b.slug}/oauth/authorize", params)

      assert redirected_to(conn) =~ "https://example.com/callback"
      assert redirected_to(conn) =~ "error=invalid_client"
    end

    test "authorization code from org A cannot be exchanged in org B", %{
      conn: conn,
      user_a: user_a,
      app_a: app_a,
      app_b: app_b,
      org_a: _org_a,
      org_b: org_b
    } do
      # Create authorization code for org A
      {:ok, auth_code} =
        Authify.OAuth.create_authorization_code(
          app_a,
          user_a,
          "https://example.com/callback",
          ["openid", "profile"]
        )

      # Try to exchange it in org B's endpoint
      params = %{
        "grant_type" => "authorization_code",
        "client_id" => app_b.client_id,
        "client_secret" => app_b.client_secret,
        "code" => auth_code.code
      }

      conn = post(conn, ~p"/#{org_b.slug}/oauth/token", params)
      response = json_response(conn, 400)
      assert response["error"] == "invalid_grant"
    end

    test "authorization code from org A cannot be exchanged with org B credentials", %{
      conn: conn,
      user_a: user_a,
      app_a: app_a,
      app_b: app_b,
      org_a: org_a
    } do
      # Create authorization code for org A
      {:ok, auth_code} =
        Authify.OAuth.create_authorization_code(
          app_a,
          user_a,
          "https://example.com/callback",
          ["openid", "profile"]
        )

      # Try to exchange it with org B's app credentials in org A's endpoint
      params = %{
        "grant_type" => "authorization_code",
        "client_id" => app_b.client_id,
        "client_secret" => app_b.client_secret,
        "code" => auth_code.code
      }

      conn = post(conn, ~p"/#{org_a.slug}/oauth/token", params)
      response = json_response(conn, 401)
      assert response["error"] == "invalid_client"
    end

    test "access token from org A cannot access userinfo in org B", %{
      conn: conn,
      user_a: user_a,
      app_a: app_a,
      org_a: _org_a,
      org_b: org_b
    } do
      # Create valid access token for org A
      {:ok, auth_code} =
        Authify.OAuth.create_authorization_code(
          app_a,
          user_a,
          "https://example.com/callback",
          ["openid", "profile", "email"]
        )

      {:ok, result} = Authify.OAuth.exchange_authorization_code(auth_code, app_a)
      access_token = result.access_token

      # Try to use it in org B's userinfo endpoint
      conn =
        conn
        |> put_req_header("authorization", "Bearer #{access_token.token}")
        |> get(~p"/#{org_b.slug}/oauth/userinfo")

      response = json_response(conn, 401)
      assert response["error"] == "invalid_token"
    end

    test "client credentials from org A cannot get token in org B", %{
      conn: conn,
      org_a: org_a,
      org_b: org_b
    } do
      # Create Management API apps for both orgs
      mgmt_app_a = management_api_application_fixture(organization: org_a)

      params = %{
        "grant_type" => "client_credentials",
        "client_id" => mgmt_app_a.client_id,
        "client_secret" => mgmt_app_a.client_secret,
        "scope" => "management_app:read"
      }

      # Try to get token from org B's endpoint
      conn = post(conn, ~p"/#{org_b.slug}/oauth/token", params)
      response = json_response(conn, 401)
      assert response["error"] == "invalid_client"
    end
  end

  describe "Authorization code validation across tenants" do
    setup do
      org_a = organization_fixture(%{name: "Organization A", slug: "org-a"})
      org_b = organization_fixture(%{name: "Organization B", slug: "org-b"})

      user_a = user_for_organization_fixture(org_a)
      user_b = user_for_organization_fixture(org_b)

      app_a = application_fixture(organization: org_a)
      app_b = application_fixture(organization: org_b)

      %{
        org_a: org_a,
        org_b: org_b,
        user_a: user_a,
        user_b: user_b,
        app_a: app_a,
        app_b: app_b
      }
    end

    test "cannot mix users and apps from different organizations", %{
      user_a: user_a,
      user_b: user_b,
      app_a: app_a,
      app_b: app_b
    } do
      # Try to create authorization code with user from org A and app from org B
      # This should fail at the service level with organization mismatch error
      assert {:error, :organization_mismatch} =
               Authify.OAuth.create_authorization_code(
                 app_b,
                 user_a,
                 "https://example.com/callback",
                 ["openid", "profile"]
               )

      # Reverse: user from org B, app from org A
      assert {:error, :organization_mismatch} =
               Authify.OAuth.create_authorization_code(
                 app_a,
                 user_b,
                 "https://example.com/callback",
                 ["openid", "profile"]
               )
    end

    test "authorization codes respect organization boundaries in database", %{
      user_a: user_a,
      user_b: user_b,
      app_a: app_a,
      app_b: app_b
    } do
      # Create valid authorization codes for each org
      {:ok, auth_code_a} =
        Authify.OAuth.create_authorization_code(
          app_a,
          user_a,
          "https://example.com/callback",
          ["openid", "profile"]
        )

      {:ok, auth_code_b} =
        Authify.OAuth.create_authorization_code(
          app_b,
          user_b,
          "https://example.com/callback",
          ["openid", "profile"]
        )

      # Verify they're properly scoped
      assert auth_code_a.application_id == app_a.id
      assert auth_code_a.user_id == user_a.id

      assert auth_code_b.application_id == app_b.id
      assert auth_code_b.user_id == user_b.id

      # Attempting to exchange with wrong app should fail
      assert {:error, :invalid_authorization_code} =
               Authify.OAuth.exchange_authorization_code(auth_code_a, app_b)

      assert {:error, :invalid_authorization_code} =
               Authify.OAuth.exchange_authorization_code(auth_code_b, app_a)
    end
  end

  describe "Access token isolation" do
    setup do
      org_a = organization_fixture(%{name: "Organization A", slug: "org-a"})
      org_b = organization_fixture(%{name: "Organization B", slug: "org-b"})

      user_a = user_for_organization_fixture(org_a)
      user_b = user_for_organization_fixture(org_b)

      app_a = application_fixture(organization: org_a)
      app_b = application_fixture(organization: org_b)

      # Create valid tokens for both orgs
      {:ok, auth_code_a} =
        Authify.OAuth.create_authorization_code(
          app_a,
          user_a,
          "https://example.com/callback",
          ["openid", "profile", "email"]
        )

      {:ok, result_a} = Authify.OAuth.exchange_authorization_code(auth_code_a, app_a)
      token_a = result_a.access_token

      {:ok, auth_code_b} =
        Authify.OAuth.create_authorization_code(
          app_b,
          user_b,
          "https://example.com/callback",
          ["openid", "profile", "email"]
        )

      {:ok, result_b} = Authify.OAuth.exchange_authorization_code(auth_code_b, app_b)
      token_b = result_b.access_token

      %{
        org_a: org_a,
        org_b: org_b,
        user_a: user_a,
        user_b: user_b,
        token_a: token_a,
        token_b: token_b
      }
    end

    test "access token from org A returns org A user info only", %{
      conn: conn,
      org_a: org_a,
      user_a: user_a,
      token_a: token_a
    } do
      conn =
        conn
        |> put_req_header("authorization", "Bearer #{token_a.token}")
        |> get(~p"/#{org_a.slug}/oauth/userinfo")

      response = json_response(conn, 200)
      assert response["sub"] == to_string(user_a.id)
      assert response["email"] == User.get_primary_email_value(user_a)
    end

    test "access token from org B returns org B user info only", %{
      conn: conn,
      org_b: org_b,
      user_b: user_b,
      token_b: token_b
    } do
      conn =
        conn
        |> put_req_header("authorization", "Bearer #{token_b.token}")
        |> get(~p"/#{org_b.slug}/oauth/userinfo")

      response = json_response(conn, 200)
      assert response["sub"] == to_string(user_b.id)
      assert response["email"] == User.get_primary_email_value(user_b)
    end

    test "tokens cannot be used across organization endpoints", %{
      conn: conn,
      org_a: org_a,
      org_b: org_b,
      token_a: token_a,
      token_b: token_b
    } do
      # Token A in org B endpoint
      conn =
        conn
        |> put_req_header("authorization", "Bearer #{token_a.token}")
        |> get(~p"/#{org_b.slug}/oauth/userinfo")

      response = json_response(conn, 401)
      assert response["error"] == "invalid_token"

      # Token B in org A endpoint
      conn =
        build_conn()
        |> put_req_header("authorization", "Bearer #{token_b.token}")
        |> get(~p"/#{org_a.slug}/oauth/userinfo")

      response = json_response(conn, 401)
      assert response["error"] == "invalid_token"
    end
  end

  describe "Management API multi-tenant isolation" do
    setup do
      org_a = organization_fixture(%{name: "Organization A", slug: "org-a"})
      org_b = organization_fixture(%{name: "Organization B", slug: "org-b"})

      mgmt_app_a = management_api_application_fixture(organization: org_a)
      mgmt_app_b = management_api_application_fixture(organization: org_b)

      %{
        org_a: org_a,
        org_b: org_b,
        mgmt_app_a: mgmt_app_a,
        mgmt_app_b: mgmt_app_b
      }
    end

    test "Management API token from org A cannot access org B resources", %{
      conn: conn,
      org_a: org_a,
      org_b: org_b,
      mgmt_app_a: mgmt_app_a
    } do
      # Get token for org A
      params = %{
        "grant_type" => "client_credentials",
        "client_id" => mgmt_app_a.client_id,
        "client_secret" => mgmt_app_a.client_secret,
        "scope" => "management_app:read users:read"
      }

      token_conn = post(conn, ~p"/#{org_a.slug}/oauth/token", params)
      token_response = json_response(token_conn, 200)
      access_token = token_response["access_token"]

      # Try to access org B's users with org A's token
      api_conn =
        conn
        |> put_req_header("authorization", "Bearer #{access_token}")
        |> put_req_header("accept", "application/vnd.authify.v1+json")

      response = get(api_conn, ~p"/#{org_b.slug}/api/users")

      # Should be unauthorized - token is for different org
      assert response.status == 401
    end

    test "Management API apps are properly isolated per organization", %{
      org_a: org_a,
      org_b: org_b,
      mgmt_app_a: mgmt_app_a,
      mgmt_app_b: mgmt_app_b
    } do
      # List Management API apps for org A
      apps_a = Authify.OAuth.list_management_api_applications(org_a)
      assert length(apps_a) == 1
      assert hd(apps_a).id == mgmt_app_a.id

      # List Management API apps for org B
      apps_b = Authify.OAuth.list_management_api_applications(org_b)
      assert length(apps_b) == 1
      assert hd(apps_b).id == mgmt_app_b.id

      # Verify they're different apps
      refute mgmt_app_a.id == mgmt_app_b.id
    end

    test "cannot create Management API token with org A app for org B", %{
      conn: conn,
      org_b: org_b,
      mgmt_app_a: mgmt_app_a
    } do
      params = %{
        "grant_type" => "client_credentials",
        "client_id" => mgmt_app_a.client_id,
        "client_secret" => mgmt_app_a.client_secret,
        "scope" => "management_app:read"
      }

      # Try to get token from org B endpoint with org A credentials
      conn = post(conn, ~p"/#{org_b.slug}/oauth/token", params)
      response = json_response(conn, 401)
      assert response["error"] == "invalid_client"
    end
  end

  describe "OIDC discovery endpoint isolation" do
    setup do
      org_a = organization_fixture(%{name: "Organization A", slug: "org-a"})
      org_b = organization_fixture(%{name: "Organization B", slug: "org-b"})

      %{org_a: org_a, org_b: org_b}
    end

    test "OIDC discovery returns correct organization-specific endpoints", %{
      conn: conn,
      org_a: org_a,
      org_b: org_b
    } do
      # Get discovery for org A
      conn_a = get(conn, ~p"/#{org_a.slug}/.well-known/openid-configuration")
      config_a = json_response(conn_a, 200)

      # Get discovery for org B
      conn_b = get(build_conn(), ~p"/#{org_b.slug}/.well-known/openid-configuration")
      config_b = json_response(conn_b, 200)

      # Verify endpoints include correct org slugs
      assert String.contains?(config_a["authorization_endpoint"], "/#{org_a.slug}/")
      assert String.contains?(config_a["token_endpoint"], "/#{org_a.slug}/")
      assert String.contains?(config_a["userinfo_endpoint"], "/#{org_a.slug}/")

      assert String.contains?(config_b["authorization_endpoint"], "/#{org_b.slug}/")
      assert String.contains?(config_b["token_endpoint"], "/#{org_b.slug}/")
      assert String.contains?(config_b["userinfo_endpoint"], "/#{org_b.slug}/")

      # Verify they're different
      refute config_a["authorization_endpoint"] == config_b["authorization_endpoint"]
    end

    @tag :skip
    test "JWKS endpoint is organization-scoped", %{
      conn: conn,
      org_a: org_a,
      org_b: org_b
    } do
      # Skipped: Organization-scoped JWKS endpoint not yet implemented.
      # See: https://github.com/authify/authify/issues/1
      # Get JWKS for org A
      conn_a = get(conn, "/#{org_a.slug}/.well-known/jwks.json")
      jwks_a = json_response(conn_a, 200)

      # Get JWKS for org B
      conn_b = get(build_conn(), "/#{org_b.slug}/.well-known/jwks.json")
      jwks_b = json_response(conn_b, 200)

      # Both should return valid JWKS structure
      assert jwks_a["keys"]
      assert jwks_b["keys"]

      # Keys should be the same for now (using same signing key)
      # In production, you might want org-specific keys
      assert is_list(jwks_a["keys"])
      assert is_list(jwks_b["keys"])
    end
  end

  describe "Cross-organization consent flow prevention" do
    setup do
      org_a = organization_fixture(%{name: "Organization A", slug: "org-a"})
      org_b = organization_fixture(%{name: "Organization B", slug: "org-b"})

      user_a = user_for_organization_fixture(org_a)
      app_b = application_fixture(organization: org_b)

      %{
        org_a: org_a,
        org_b: org_b,
        user_a: user_a,
        app_b: app_b
      }
    end

    test "user from org A cannot consent to app from org B", %{
      conn: conn,
      user_a: user_a,
      app_b: app_b,
      org_a: org_a
    } do
      conn = log_in_user(conn, user_a)

      # Try to submit consent for org B's app through org A's endpoint
      params = %{
        "client_id" => app_b.client_id,
        "redirect_uri" => "https://example.com/callback",
        "scope" => "openid profile",
        "approve" => "true"
      }

      conn = post(conn, ~p"/#{org_a.slug}/oauth/consent", params)

      # Should redirect with error
      assert redirected_to(conn) =~ "https://example.com/callback"
      assert redirected_to(conn) =~ "error="
    end

    test "cannot bypass org check by posting directly to consent endpoint", %{
      conn: conn,
      user_a: user_a,
      app_b: app_b,
      org_b: org_b
    } do
      conn = log_in_user(conn, user_a)

      # Try to submit consent to org B's endpoint (user logged into org A)
      params = %{
        "client_id" => app_b.client_id,
        "redirect_uri" => "https://example.com/callback",
        "scope" => "openid profile",
        "approve" => "true"
      }

      conn = post(conn, ~p"/#{org_b.slug}/oauth/consent", params)

      # Should fail - user session should be org-scoped or re-authenticated
      assert redirected_to(conn) =~ "https://example.com/callback"
      assert redirected_to(conn) =~ "error="
    end
  end
end
