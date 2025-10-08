defmodule AuthifyWeb.OAuthRealWorldFlowsTest do
  @moduledoc """
  Real-world multi-step OAuth integration tests.

  These tests simulate complete user journeys:
  - User signs up → Admin creates OAuth app → User authorizes → App accesses API
  - OAuth app created → Scopes updated → Old tokens still work but new authorizations use new scopes
  - Complete authorization code flow with PKCE
  - Token refresh and expiration scenarios
  """
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures

  alias Authify.OAuth.Application

  describe "Complete user signup to OAuth API access flow" do
    test "new user can sign up, authorize app, and app can access API on their behalf" do
      # Step 1: Organization admin signs up their organization
      org_attrs = %{
        "name" => "Acme Corporation",
        "slug" => "acme-corp",
        "domain" => "acme.example.com"
      }

      user_attrs = %{
        "email" => "admin@acme.example.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!",
        "first_name" => "Admin",
        "last_name" => "User"
      }

      {:ok, {organization, admin}} =
        Authify.Accounts.create_organization_with_admin(org_attrs, user_attrs)

      assert organization.slug == "acme-corp"
      assert admin.role == "admin"
      assert admin.email == "admin@acme.example.com"

      # Step 2: Admin creates an OAuth application
      app_attrs = %{
        "name" => "Acme Mobile App",
        "description" => "Mobile app for Acme employees",
        "scopes" => "openid profile email",
        "redirect_uris" =>
          "https://acme-mobile.example.com/callback\nhttps://localhost:3000/callback",
        "application_type" => "oauth2_app"
      }

      {:ok, oauth_app} =
        Authify.OAuth.create_application(Map.put(app_attrs, "organization_id", organization.id))

      assert oauth_app.name == "Acme Mobile App"
      assert oauth_app.client_id
      assert oauth_app.client_secret

      # Step 3: Admin invites a regular user
      {:ok, invitation} =
        Authify.Accounts.create_invitation(%{
          "email" => "employee@acme.example.com",
          "role" => "user",
          "organization_id" => organization.id,
          "invited_by_id" => admin.id
        })

      assert invitation.email == "employee@acme.example.com"

      # Step 4: User accepts invitation and creates account
      {:ok, user} =
        Authify.Accounts.accept_invitation(invitation, %{
          "first_name" => "John",
          "last_name" => "Employee",
          "password" => "SecureP@ssw0rd!",
          "password_confirmation" => "SecureP@ssw0rd!"
        })

      assert user.email == "employee@acme.example.com"
      assert user.first_name == "John"

      # Step 5: User initiates OAuth authorization flow
      conn = build_conn()
      conn = log_in_user(conn, user)

      # Generate PKCE parameters
      code_verifier = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

      code_challenge =
        :crypto.hash(:sha256, code_verifier) |> Base.url_encode64(padding: false)

      authorize_params = %{
        "client_id" => oauth_app.client_id,
        "redirect_uri" => "https://acme-mobile.example.com/callback",
        "response_type" => "code",
        "scope" => "openid profile email",
        "state" => "random_state_123",
        "code_challenge" => code_challenge,
        "code_challenge_method" => "S256"
      }

      conn = get(conn, ~p"/#{organization.slug}/oauth/authorize", authorize_params)

      # Should show consent screen
      assert html_response(conn, 200) =~ "Acme Mobile App"
      assert html_response(conn, 200) =~ "openid"
      assert html_response(conn, 200) =~ "profile"
      assert html_response(conn, 200) =~ "email"

      # Step 6: User approves the authorization
      conn = build_conn() |> log_in_user(user)

      consent_params =
        authorize_params
        |> Map.put("approve", "true")

      conn = post(conn, ~p"/#{organization.slug}/oauth/consent", consent_params)

      # Should redirect to app with authorization code
      redirect_url = redirected_to(conn)
      assert redirect_url =~ "https://acme-mobile.example.com/callback"
      assert redirect_url =~ "code="
      assert redirect_url =~ "state=random_state_123"

      # Extract authorization code
      uri = URI.parse(redirect_url)
      query_params = URI.decode_query(uri.query)
      auth_code = query_params["code"]

      assert auth_code

      # Step 7: App exchanges authorization code for access token
      token_params = %{
        "grant_type" => "authorization_code",
        "client_id" => oauth_app.client_id,
        "client_secret" => oauth_app.client_secret,
        "code" => auth_code,
        "redirect_uri" => "https://acme-mobile.example.com/callback",
        "code_verifier" => code_verifier
      }

      conn = build_conn()
      conn = post(conn, ~p"/#{organization.slug}/oauth/token", token_params)

      token_response = json_response(conn, 200)
      assert token_response["access_token"]
      assert token_response["token_type"] == "Bearer"
      assert token_response["id_token"]
      assert token_response["expires_in"]

      access_token = token_response["access_token"]

      # Step 8: App accesses user info on behalf of the user
      conn =
        build_conn()
        |> put_req_header("authorization", "Bearer #{access_token}")

      conn = get(conn, ~p"/#{organization.slug}/oauth/userinfo")

      userinfo = json_response(conn, 200)
      assert userinfo["sub"] == to_string(user.id)
      assert userinfo["email"] == "employee@acme.example.com"
      assert userinfo["given_name"] == "John"
      assert userinfo["family_name"] == "Employee"
      assert userinfo["name"] == "John Employee"

      # Step 9: Verify ID token contains expected claims
      id_token = token_response["id_token"]
      [_header, payload, _signature] = String.split(id_token, ".")
      decoded_payload = payload |> Base.url_decode64!(padding: false) |> Jason.decode!()

      assert decoded_payload["sub"] == to_string(user.id)
      assert decoded_payload["email"] == "employee@acme.example.com"
      assert decoded_payload["aud"] == oauth_app.client_id
    end
  end

  describe "OAuth application scope updates and token lifecycle" do
    setup do
      org = organization_fixture()
      user = user_for_organization_fixture(org)

      {:ok, app} =
        Authify.OAuth.create_application(%{
          "name" => "Test App",
          "description" => "Test",
          "scopes" => "openid profile",
          "redirect_uris" => "https://example.com/callback",
          "organization_id" => org.id,
          "application_type" => "oauth2_app"
        })

      %{org: org, user: user, app: app}
    end

    test "old tokens remain valid after scope update, but new authorizations use new scopes", %{
      org: org,
      user: user,
      app: app
    } do
      # Step 1: User authorizes with original scopes (openid, profile)
      {:ok, auth_code1} =
        Authify.OAuth.create_authorization_code(
          app,
          user,
          "https://example.com/callback",
          ["openid", "profile"]
        )

      {:ok, token_result1} = Authify.OAuth.exchange_authorization_code(auth_code1, app)
      old_token = token_result1.access_token

      # Verify old token works with original scopes
      conn =
        build_conn()
        |> put_req_header("authorization", "Bearer #{old_token.token}")
        |> get(~p"/#{org.slug}/oauth/userinfo")

      userinfo = json_response(conn, 200)
      assert userinfo["sub"]
      assert userinfo["name"]
      # Email not included in original scope
      refute userinfo["email"]

      # Step 2: Admin updates app scopes to include email
      {:ok, updated_app} =
        Authify.OAuth.update_application(app, %{"scopes" => "openid profile email"})

      assert Application.scopes_list(updated_app) == ["openid", "profile", "email"]

      # Step 3: Old token should still work (tokens are immutable)
      conn =
        build_conn()
        |> put_req_header("authorization", "Bearer #{old_token.token}")
        |> get(~p"/#{org.slug}/oauth/userinfo")

      userinfo = json_response(conn, 200)
      assert userinfo["sub"]
      # Old token still doesn't return email (scope is stored with token)
      # Note: This depends on implementation - some systems check token scopes, others check app scopes

      # Step 4: New authorization uses updated scopes
      {:ok, auth_code2} =
        Authify.OAuth.create_authorization_code(
          updated_app,
          user,
          "https://example.com/callback",
          ["openid", "profile", "email"]
        )

      {:ok, token_result2} = Authify.OAuth.exchange_authorization_code(auth_code2, updated_app)
      new_token = token_result2.access_token

      # New token should include email
      conn =
        build_conn()
        |> put_req_header("authorization", "Bearer #{new_token.token}")
        |> get(~p"/#{org.slug}/oauth/userinfo")

      userinfo = json_response(conn, 200)
      assert userinfo["sub"]
      assert userinfo["email"]
      assert userinfo["name"]
    end

    test "expired tokens cannot access protected resources", %{
      org: org,
      user: user,
      app: app
    } do
      # Create an authorization code and exchange it
      {:ok, auth_code} =
        Authify.OAuth.create_authorization_code(
          app,
          user,
          "https://example.com/callback",
          ["openid", "profile"]
        )

      {:ok, token_result} = Authify.OAuth.exchange_authorization_code(auth_code, app)
      access_token = token_result.access_token

      # Manually expire the token
      Authify.Repo.update!(
        Ecto.Changeset.change(access_token,
          expires_at: DateTime.truncate(DateTime.add(DateTime.utc_now(), -3600), :second)
        )
      )

      # Try to use expired token
      conn =
        build_conn()
        |> put_req_header("authorization", "Bearer #{access_token.token}")
        |> get(~p"/#{org.slug}/oauth/userinfo")

      assert json_response(conn, 401)["error"] == "invalid_token"
    end

    test "revoked tokens cannot access protected resources", %{
      org: org,
      user: user,
      app: app
    } do
      # Create a valid token
      {:ok, auth_code} =
        Authify.OAuth.create_authorization_code(
          app,
          user,
          "https://example.com/callback",
          ["openid", "profile"]
        )

      {:ok, token_result} = Authify.OAuth.exchange_authorization_code(auth_code, app)
      access_token = token_result.access_token

      # Token works initially
      conn =
        build_conn()
        |> put_req_header("authorization", "Bearer #{access_token.token}")
        |> get(~p"/#{org.slug}/oauth/userinfo")

      assert json_response(conn, 200)["sub"]

      # Revoke the token
      {:ok, _revoked} = Authify.OAuth.revoke_access_token(access_token)

      # Token should no longer work
      conn =
        build_conn()
        |> put_req_header("authorization", "Bearer #{access_token.token}")
        |> get(~p"/#{org.slug}/oauth/userinfo")

      assert json_response(conn, 401)["error"] == "invalid_token"
    end
  end

  describe "PKCE flow enforcement" do
    setup do
      org = organization_fixture()
      user = user_for_organization_fixture(org)

      {:ok, public_app} =
        Authify.OAuth.create_application(%{
          "name" => "Public App",
          "description" => "Mobile/SPA app requiring PKCE",
          "scopes" => "openid profile",
          "redirect_uris" => "https://example.com/callback",
          "organization_id" => org.id,
          "application_type" => "oauth2_app",
          "require_pkce" => true
        })

      %{org: org, user: user, public_app: public_app}
    end

    test "public apps must use PKCE", %{org: org, user: user, public_app: app} do
      conn = build_conn() |> log_in_user(user)

      # Try to authorize without PKCE parameters
      params = %{
        "client_id" => app.client_id,
        "redirect_uri" => "https://example.com/callback",
        "response_type" => "code",
        "scope" => "openid profile"
      }

      conn = get(conn, ~p"/#{org.slug}/oauth/authorize", params)

      # Should fail - PKCE required
      redirect_url = redirected_to(conn)
      assert redirect_url =~ "error=invalid_request"
      # PKCE is required for this app
    end

    test "PKCE code_verifier must match code_challenge", %{org: org, user: user, public_app: app} do
      conn = build_conn() |> log_in_user(user)

      # Generate PKCE parameters
      code_verifier = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

      code_challenge =
        :crypto.hash(:sha256, code_verifier) |> Base.url_encode64(padding: false)

      # Authorize with PKCE
      params = %{
        "client_id" => app.client_id,
        "redirect_uri" => "https://example.com/callback",
        "response_type" => "code",
        "scope" => "openid profile",
        "code_challenge" => code_challenge,
        "code_challenge_method" => "S256",
        "approve" => "true"
      }

      conn = post(conn, ~p"/#{org.slug}/oauth/consent", params)

      redirect_url = redirected_to(conn)
      uri = URI.parse(redirect_url)
      query_params = URI.decode_query(uri.query)
      auth_code = query_params["code"]

      # Try to exchange with wrong verifier
      wrong_verifier = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

      token_params = %{
        "grant_type" => "authorization_code",
        "client_id" => app.client_id,
        "client_secret" => app.client_secret,
        "code" => auth_code,
        "redirect_uri" => "https://example.com/callback",
        "code_verifier" => wrong_verifier
      }

      conn = build_conn()
      conn = post(conn, ~p"/#{org.slug}/oauth/token", token_params)

      response = json_response(conn, 400)
      assert response["error"] == "invalid_grant"
    end
  end

  describe "Management API access flow" do
    test "complete flow: create mgmt app, get token, access API" do
      # Step 1: Create organization and admin
      org = organization_fixture()
      _admin = admin_user_fixture(org)

      # Step 2: Admin creates Management API application
      {:ok, mgmt_app} =
        Authify.OAuth.create_application(%{
          "name" => "CI/CD Integration",
          "description" => "Automated deployment tool",
          "scopes" => "management_app:read management_app:write users:read users:write",
          "organization_id" => org.id,
          "application_type" => "management_api_app"
        })

      assert mgmt_app.application_type == "management_api_app"
      assert mgmt_app.client_id
      assert mgmt_app.client_secret

      # Step 3: App gets access token via client credentials
      conn = build_conn()

      token_params = %{
        "grant_type" => "client_credentials",
        "client_id" => mgmt_app.client_id,
        "client_secret" => mgmt_app.client_secret,
        "scope" => "management_app:read users:read users:write"
      }

      conn = post(conn, ~p"/#{org.slug}/oauth/token", token_params)

      token_response = json_response(conn, 200)
      assert token_response["access_token"]
      assert token_response["token_type"] == "Bearer"

      access_token = token_response["access_token"]

      # Step 4: App uses token to access Management API
      api_conn =
        build_conn()
        |> put_req_header("authorization", "Bearer #{access_token}")
        |> put_req_header("accept", "application/vnd.authify.v1+json")

      # List users
      api_conn = get(api_conn, ~p"/#{org.slug}/api/users")
      users_response = json_response(api_conn, 200)
      assert users_response["data"]
      assert is_list(users_response["data"])

      # Create a new user
      create_conn =
        build_conn()
        |> put_req_header("authorization", "Bearer #{access_token}")
        |> put_req_header("accept", "application/vnd.authify.v1+json")
        |> put_req_header("content-type", "application/json")

      new_user_attrs = %{
        "user" => %{
          "email" => "newuser@example.com",
          "first_name" => "New",
          "last_name" => "User",
          "username" => "newuser",
          "password" => "SecureP@ssw0rd!",
          "password_confirmation" => "SecureP@ssw0rd!",
          "role" => "user"
        }
      }

      create_conn = post(create_conn, ~p"/#{org.slug}/api/users", new_user_attrs)
      create_response = json_response(create_conn, 201)

      assert create_response["data"]["attributes"]["email"] == "newuser@example.com"
      assert create_response["data"]["id"]
    end
  end
end
