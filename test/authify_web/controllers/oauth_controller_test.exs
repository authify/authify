defmodule AuthifyWeb.OAuthControllerTest do
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures
  import Authify.OAuthFixtures

  alias Authify.Accounts
  alias Authify.Accounts.User

  describe "authorize" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      application = application_fixture(organization: organization)

      %{
        organization: organization,
        user: user,
        application: application
      }
    end

    test "redirects to login when user not authenticated", %{
      conn: conn,
      application: application,
      organization: organization
    } do
      params = %{
        "client_id" => application.client_id,
        "redirect_uri" => "https://example.com/callback",
        "response_type" => "code",
        "scope" => "openid profile"
      }

      conn = get(conn, ~p"/#{organization.slug}/oauth/authorize", params)
      assert redirected_to(conn) =~ "/login"
    end

    test "shows consent screen when user authenticated", %{
      conn: conn,
      user: user,
      application: application,
      organization: organization
    } do
      conn = log_in_user(conn, user)

      params = %{
        "client_id" => application.client_id,
        "redirect_uri" => "https://example.com/callback",
        "response_type" => "code",
        "scope" => "openid profile"
      }

      conn = get(conn, ~p"/#{organization.slug}/oauth/authorize", params)
      assert html_response(conn, 200) =~ "Authorize Application"
      assert html_response(conn, 200) =~ application.name
    end

    test "returns error for invalid client_id", %{
      conn: conn,
      user: user,
      organization: organization
    } do
      conn = log_in_user(conn, user)

      params = %{
        "client_id" => "invalid_client_id",
        "redirect_uri" => "https://example.com/callback",
        "response_type" => "code"
      }

      conn = get(conn, ~p"/#{organization.slug}/oauth/authorize", params)
      assert redirected_to(conn) =~ "https://example.com/callback"
      assert redirected_to(conn) =~ "error=invalid_client"
    end
  end

  describe "consent" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      application = application_fixture(organization: organization)

      %{
        organization: organization,
        user: user,
        application: application
      }
    end

    test "creates authorization code when approved", %{
      conn: conn,
      user: user,
      application: application,
      organization: organization
    } do
      conn = log_in_user(conn, user)

      params = %{
        "client_id" => application.client_id,
        "redirect_uri" => "https://example.com/callback",
        "scope" => "openid profile",
        "approve" => "true"
      }

      conn = post(conn, ~p"/#{organization.slug}/oauth/consent", params)
      assert redirected_to(conn) =~ "https://example.com/callback"
      assert redirected_to(conn) =~ "code="
    end

    test "redirects with error when denied", %{
      conn: conn,
      user: user,
      application: application,
      organization: organization
    } do
      conn = log_in_user(conn, user)

      params = %{
        "client_id" => application.client_id,
        "redirect_uri" => "https://example.com/callback",
        "scope" => "openid profile",
        "approve" => "false"
      }

      conn = post(conn, ~p"/#{organization.slug}/oauth/consent", params)
      assert redirected_to(conn) =~ "https://example.com/callback"
      assert redirected_to(conn) =~ "error=access_denied"
    end
  end

  describe "token" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      application = application_fixture(organization: organization)

      {:ok, auth_code} =
        Authify.OAuth.create_authorization_code(
          application,
          user,
          "https://example.com/callback",
          ["openid", "profile"]
        )

      %{
        organization: organization,
        user: user,
        application: application,
        auth_code: auth_code
      }
    end

    test "exchanges valid authorization code for access token", %{
      conn: conn,
      application: application,
      auth_code: auth_code,
      organization: organization
    } do
      params = %{
        "grant_type" => "authorization_code",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret,
        "code" => auth_code.code
      }

      conn = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      response = json_response(conn, 200)

      assert response["access_token"]
      assert response["token_type"] == "Bearer"
      assert response["expires_in"] == 3600
      # Should include ID token for OIDC
      assert response["id_token"]
    end

    test "returns error for invalid authorization code", %{
      conn: conn,
      application: application,
      organization: organization
    } do
      params = %{
        "grant_type" => "authorization_code",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret,
        "code" => "invalid_code"
      }

      conn = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      response = json_response(conn, 400)
      assert response["error"] == "invalid_grant"
    end

    test "returns error for invalid client credentials", %{
      conn: conn,
      auth_code: auth_code,
      organization: organization
    } do
      params = %{
        "grant_type" => "authorization_code",
        "client_id" => "invalid_client",
        "client_secret" => "invalid_secret",
        "code" => auth_code.code
      }

      conn = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      response = json_response(conn, 401)
      assert response["error"] == "invalid_client"
    end
  end

  describe "client credentials token" do
    setup do
      organization = organization_fixture()
      application = management_api_application_fixture(organization: organization)

      %{
        organization: organization,
        application: application
      }
    end

    test "exchanges client credentials for Management API access token", %{
      conn: conn,
      application: application,
      organization: organization
    } do
      params = %{
        "grant_type" => "client_credentials",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret,
        "scope" => "management_app:read users:read"
      }

      conn = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      response = json_response(conn, 200)

      assert response["access_token"]
      assert response["token_type"] == "Bearer"
      assert response["expires_in"] == 3600
      assert response["scope"] == "management_app:read users:read"
      # Should NOT include ID token for client credentials
      refute response["id_token"]
    end

    test "returns all granted scopes when scope parameter is omitted", %{
      conn: conn,
      application: application,
      organization: organization
    } do
      params = %{
        "grant_type" => "client_credentials",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret
        # No scope parameter - should get all granted scopes
      }

      conn = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      response = json_response(conn, 200)

      assert response["access_token"]
      # Should receive all scopes granted to the application
      granted_scopes = Authify.Scopes.management_api_scopes()
      returned_scopes = String.split(response["scope"], " ")
      assert Enum.sort(returned_scopes) == Enum.sort(granted_scopes)
    end

    test "allows requesting subset of granted scopes", %{
      conn: conn,
      application: application,
      organization: organization
    } do
      params = %{
        "grant_type" => "client_credentials",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret,
        "scope" => "users:read"
      }

      conn = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      response = json_response(conn, 200)

      assert response["access_token"]
      assert response["scope"] == "users:read"
    end

    test "returns error for scope not granted to application", %{
      conn: conn,
      application: application,
      organization: organization
    } do
      params = %{
        "grant_type" => "client_credentials",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret,
        # PAT-only scope, not granted to this app
        "scope" => "profile:read"
      }

      conn = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      response = json_response(conn, 400)
      assert response["error"] == "invalid_scope"
    end

    test "returns error for invalid scope in client credentials", %{
      conn: conn,
      application: application,
      organization: organization
    } do
      params = %{
        "grant_type" => "client_credentials",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret,
        "scope" => "invalid:scope"
      }

      conn = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      response = json_response(conn, 400)
      assert response["error"] == "invalid_scope"
    end

    test "returns error for OAuth2 app trying to use client credentials", %{
      conn: conn,
      organization: organization
    } do
      # Use organization from setup instead of creating a new one
      # organization = organization_fixture()
      # This creates oauth2_app
      oauth_app = application_fixture(organization: organization)

      params = %{
        "grant_type" => "client_credentials",
        "client_id" => oauth_app.client_id,
        "client_secret" => oauth_app.client_secret,
        "scope" => "management_app:read"
      }

      conn = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      response = json_response(conn, 400)
      assert response["error"] == "unauthorized_client"
      assert String.contains?(response["error_description"], "client_credentials grant type")
    end
  end

  describe "userinfo" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      application = application_fixture(organization: organization)

      {:ok, auth_code} =
        Authify.OAuth.create_authorization_code(
          application,
          user,
          "https://example.com/callback",
          ["openid", "profile", "email"]
        )

      {:ok, result} = Authify.OAuth.exchange_authorization_code(auth_code, application)

      %{
        organization: organization,
        user: user,
        access_token: result.access_token
      }
    end

    test "returns user info for valid access token", %{
      conn: conn,
      user: user,
      access_token: access_token,
      organization: organization
    } do
      conn =
        conn
        |> put_req_header("authorization", "Bearer #{access_token.token}")
        |> get(~p"/#{organization.slug}/oauth/userinfo")

      response = json_response(conn, 200)
      assert response["sub"] == to_string(user.id)
      assert response["email"] == User.get_primary_email_value(user)
      assert response["name"]
    end

    test "returns error for missing token", %{conn: conn, organization: organization} do
      conn = get(conn, ~p"/#{organization.slug}/oauth/userinfo")
      response = json_response(conn, 401)
      assert response["error"] == "invalid_request"
    end

    test "returns error for invalid token", %{conn: conn, organization: organization} do
      conn =
        conn
        |> put_req_header("authorization", "Bearer invalid_token")
        |> get(~p"/#{organization.slug}/oauth/userinfo")

      response = json_response(conn, 401)
      assert response["error"] == "invalid_token"
    end

    test "returns error for expired token", %{conn: conn, user: user, organization: organization} do
      # organization = user.organization  # Already available from setup
      application = application_fixture(organization: organization)

      # Create expired access token by manually inserting with expired time
      expired_time =
        DateTime.utc_now() |> DateTime.add(-3600, :second) |> DateTime.truncate(:second)

      token_value =
        "expired_test_token_#{:crypto.strong_rand_bytes(16) |> Base.hex_encode32(case: :lower)}"

      {:ok, expired_token} =
        %Authify.OAuth.AccessToken{
          token: token_value,
          expires_at: expired_time,
          scopes: "openid profile",
          user_id: user.id,
          application_id: application.id,
          inserted_at: DateTime.utc_now() |> DateTime.truncate(:second),
          updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
        }
        |> Authify.Repo.insert()

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{expired_token.token}")
        |> get(~p"/#{organization.slug}/oauth/userinfo")

      response = json_response(conn, 401)
      assert response["error"] == "invalid_token"
    end

    test "returns groups claim when groups scope is requested", %{
      conn: conn,
      user: user,
      organization: organization
    } do
      # Create groups
      {:ok, group1} =
        Authify.Accounts.create_group(%{
          "name" => "Developers",
          "description" => "Development team",
          "organization_id" => organization.id
        })

      {:ok, group2} =
        Authify.Accounts.create_group(%{
          "name" => "Admins",
          "description" => "Admin team",
          "organization_id" => organization.id
        })

      # Add user to groups
      {:ok, _} = Authify.Accounts.add_user_to_group(user, group1)
      {:ok, _} = Authify.Accounts.add_user_to_group(user, group2)

      # Create application and access token with groups scope
      application = application_fixture(organization: organization)

      {:ok, auth_code} =
        Authify.OAuth.create_authorization_code(
          application,
          user,
          "https://example.com/callback",
          ["openid", "profile", "email", "groups"]
        )

      {:ok, result} = Authify.OAuth.exchange_authorization_code(auth_code, application)

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{result.access_token.token}")
        |> get(~p"/#{organization.slug}/oauth/userinfo")

      response = json_response(conn, 200)
      assert response["sub"] == to_string(user.id)
      assert response["email"] == User.get_primary_email_value(user)
      assert is_list(response["groups"])
      assert "Developers" in response["groups"]
      assert "Admins" in response["groups"]
      assert length(response["groups"]) == 2
    end

    test "does not return groups claim when groups scope is not requested", %{
      conn: conn,
      user: user,
      organization: organization
    } do
      # Create a group and add user to it
      {:ok, group} =
        Authify.Accounts.create_group(%{
          "name" => "Test Group",
          "description" => "Test",
          "organization_id" => organization.id
        })

      {:ok, _} = Authify.Accounts.add_user_to_group(user, group)

      # Create application and access token WITHOUT groups scope
      application = application_fixture(organization: organization)

      {:ok, auth_code} =
        Authify.OAuth.create_authorization_code(
          application,
          user,
          "https://example.com/callback",
          ["openid", "profile", "email"]
        )

      {:ok, result} = Authify.OAuth.exchange_authorization_code(auth_code, application)

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{result.access_token.token}")
        |> get(~p"/#{organization.slug}/oauth/userinfo")

      response = json_response(conn, 200)
      assert response["sub"] == to_string(user.id)
      assert response["email"] == User.get_primary_email_value(user)
      refute Map.has_key?(response, "groups")
    end

    test "returns empty groups array when user has no groups", %{
      conn: conn,
      user: user,
      organization: organization
    } do
      # Create application and access token with groups scope
      application = application_fixture(organization: organization)

      {:ok, auth_code} =
        Authify.OAuth.create_authorization_code(
          application,
          user,
          "https://example.com/callback",
          ["openid", "groups"]
        )

      {:ok, result} = Authify.OAuth.exchange_authorization_code(auth_code, application)

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{result.access_token.token}")
        |> get(~p"/#{organization.slug}/oauth/userinfo")

      response = json_response(conn, 200)
      assert response["sub"] == to_string(user.id)
      assert response["groups"] == []
    end
  end

  describe "OAuth security and edge cases" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      application = application_fixture(organization: organization)

      %{organization: organization, user: user, application: application}
    end

    test "authorization code can only be used once", %{
      conn: conn,
      application: application,
      user: user,
      organization: organization
    } do
      {:ok, auth_code} =
        Authify.OAuth.create_authorization_code(
          application,
          user,
          "https://example.com/callback",
          ["openid", "profile"]
        )

      params = %{
        "grant_type" => "authorization_code",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret,
        "code" => auth_code.code
      }

      # First exchange should succeed
      conn1 = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      response1 = json_response(conn1, 200)
      assert response1["access_token"]

      # Second exchange should fail
      conn2 = post(build_conn(), ~p"/#{organization.slug}/oauth/token", params)
      response2 = json_response(conn2, 400)
      assert response2["error"] == "invalid_grant"
    end

    test "authorization code expires after timeout", %{
      conn: conn,
      application: application,
      user: user,
      organization: organization
    } do
      # Create expired authorization code
      # 10 minutes ago
      expired_time =
        DateTime.utc_now() |> DateTime.add(-600, :second) |> DateTime.truncate(:second)

      {:ok, expired_auth_code} =
        %Authify.OAuth.AuthorizationCode{}
        |> Authify.OAuth.AuthorizationCode.changeset(%{
          code:
            "expired_code_#{:crypto.strong_rand_bytes(16) |> Base.hex_encode32(case: :lower)}",
          redirect_uri: "https://example.com/callback",
          scopes: "openid profile",
          expires_at: expired_time,
          user_id: user.id,
          application_id: application.id
        })
        |> Authify.Repo.insert()

      params = %{
        "grant_type" => "authorization_code",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret,
        "code" => expired_auth_code.code
      }

      conn = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      response = json_response(conn, 400)
      assert response["error"] == "invalid_grant"
    end

    test "validates redirect_uri matches registered URIs", %{
      conn: conn,
      user: user,
      application: application,
      organization: organization
    } do
      conn = log_in_user(conn, user)

      # Valid redirect URI should work
      valid_params = %{
        "client_id" => application.client_id,
        "redirect_uri" => "https://example.com/callback",
        "response_type" => "code",
        "scope" => "openid profile"
      }

      conn = get(conn, ~p"/#{organization.slug}/oauth/authorize", valid_params)
      assert html_response(conn, 200) =~ "Authorize Application"

      # Invalid redirect URI should fail
      invalid_params = %{
        "client_id" => application.client_id,
        "redirect_uri" => "https://evil.com/steal-codes",
        "response_type" => "code",
        "scope" => "openid profile"
      }

      conn =
        get(
          build_conn() |> log_in_user(user),
          ~p"/#{organization.slug}/oauth/authorize",
          invalid_params
        )

      assert redirected_to(conn) =~ "https://evil.com/steal-codes"
      assert redirected_to(conn) =~ "error=invalid_redirect_uri"
    end

    test "validates client_secret for confidential clients", %{
      conn: conn,
      application: application,
      user: user,
      organization: organization
    } do
      {:ok, auth_code} =
        Authify.OAuth.create_authorization_code(
          application,
          user,
          "https://example.com/callback",
          ["openid", "profile"]
        )

      # Valid client_secret should work
      valid_params = %{
        "grant_type" => "authorization_code",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret,
        "code" => auth_code.code
      }

      conn = post(conn, ~p"/#{organization.slug}/oauth/token", valid_params)
      response = json_response(conn, 200)
      assert response["access_token"]

      # Create new auth code for next test
      {:ok, auth_code2} =
        Authify.OAuth.create_authorization_code(
          application,
          user,
          "https://example.com/callback",
          ["openid", "profile"]
        )

      # Invalid client_secret should fail
      invalid_params = %{
        "grant_type" => "authorization_code",
        "client_id" => application.client_id,
        "client_secret" => "wrong_secret",
        "code" => auth_code2.code
      }

      conn = post(build_conn(), ~p"/#{organization.slug}/oauth/token", invalid_params)
      response = json_response(conn, 401)
      assert response["error"] == "invalid_client"
    end

    test "scopes are properly enforced", %{
      conn: conn,
      application: application,
      user: user,
      organization: organization
    } do
      # Create token with limited scopes
      {:ok, auth_code} =
        Authify.OAuth.create_authorization_code(
          application,
          user,
          "https://example.com/callback",
          # Only openid, no profile or email
          ["openid"]
        )

      {:ok, result} = Authify.OAuth.exchange_authorization_code(auth_code, application)
      limited_token = result.access_token

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{limited_token.token}")
        |> get(~p"/#{organization.slug}/oauth/userinfo")

      response = json_response(conn, 200)
      # Should have sub (from openid)
      assert response["sub"]
      # Should not have email claim
      refute Map.has_key?(response, "email")
      # Should not have name claim
      refute Map.has_key?(response, "name")
    end
  end

  describe "OIDC compliance" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      application = application_fixture(organization: organization)

      %{organization: organization, user: user, application: application}
    end

    test "ID token contains required OIDC claims", %{
      conn: conn,
      application: application,
      user: user,
      organization: organization
    } do
      {:ok, auth_code} =
        Authify.OAuth.create_authorization_code(
          application,
          user,
          "https://example.com/callback",
          ["openid", "profile", "email"]
        )

      params = %{
        "grant_type" => "authorization_code",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret,
        "code" => auth_code.code
      }

      conn = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      response = json_response(conn, 200)

      # Decode ID token (without signature verification for testing)
      id_token = response["id_token"]
      [_header, payload, _signature] = String.split(id_token, ".")

      # Decode base64url payload
      payload_json =
        payload
        |> Base.url_decode64!(padding: false)
        |> Jason.decode!()

      # Check required OIDC claims
      # Issuer
      assert payload_json["iss"]
      # Subject
      assert payload_json["sub"]
      # Audience
      assert payload_json["aud"] == application.client_id
      # Expiration time
      assert payload_json["exp"]
      # Issued at time
      assert payload_json["iat"]
    end

    test "ID token is RS256-signed with three segments", %{
      conn: conn,
      application: application,
      user: user,
      organization: organization
    } do
      {:ok, auth_code} =
        Authify.OAuth.create_authorization_code(
          application,
          user,
          "https://example.com/callback",
          ["openid"]
        )

      params = %{
        "grant_type" => "authorization_code",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret,
        "code" => auth_code.code
      }

      conn = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      response = json_response(conn, 200)

      id_token = response["id_token"]

      # Must have exactly three dot-separated segments (header.claims.signature)
      segments = String.split(id_token, ".")
      assert length(segments) == 3

      [encoded_header, _encoded_claims, encoded_sig] = segments

      header_json =
        encoded_header
        |> Base.url_decode64!(padding: false)
        |> Jason.decode!()

      # Header must declare RS256, not "none"
      assert header_json["alg"] == "RS256"
      assert header_json["typ"] == "JWT"
      assert is_binary(header_json["kid"])

      # Signature segment must be non-empty (unlike alg:none)
      assert byte_size(encoded_sig) > 0
    end

    test "ID token kid matches the org's active OAuth signing cert", %{
      conn: conn,
      application: application,
      user: user,
      organization: organization
    } do
      # Ensure an OAuth signing cert is pre-created so we know its id
      {:ok, cert} =
        Accounts.get_or_generate_oauth_signing_certificate(organization)

      {:ok, auth_code} =
        Authify.OAuth.create_authorization_code(
          application,
          user,
          "https://example.com/callback",
          ["openid"]
        )

      params = %{
        "grant_type" => "authorization_code",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret,
        "code" => auth_code.code
      }

      conn = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      response = json_response(conn, 200)

      [encoded_header | _] = String.split(response["id_token"], ".")

      header_json =
        encoded_header
        |> Base.url_decode64!(padding: false)
        |> Jason.decode!()

      assert header_json["kid"] == to_string(cert.id)
    end

    test "ID token iss matches the org-scoped URL", %{
      conn: conn,
      application: application,
      user: user,
      organization: organization
    } do
      {:ok, auth_code} =
        Authify.OAuth.create_authorization_code(
          application,
          user,
          "https://example.com/callback",
          ["openid"]
        )

      params = %{
        "grant_type" => "authorization_code",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret,
        "code" => auth_code.code
      }

      conn = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      response = json_response(conn, 200)

      [_header, encoded_claims | _] = String.split(response["id_token"], ".")

      claims =
        encoded_claims
        |> Base.url_decode64!(padding: false)
        |> Jason.decode!()

      expected_iss = "#{AuthifyWeb.Endpoint.url()}/#{organization.slug}"
      assert claims["iss"] == expected_iss
    end

    test "token response without openid scope has no id_token", %{
      conn: conn,
      application: application,
      user: user,
      organization: organization
    } do
      {:ok, auth_code} =
        Authify.OAuth.create_authorization_code(
          application,
          user,
          "https://example.com/callback",
          ["profile", "email"]
        )

      params = %{
        "grant_type" => "authorization_code",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret,
        "code" => auth_code.code
      }

      conn = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      response = json_response(conn, 200)

      refute Map.has_key?(response, "id_token")
    end

    test "refresh token grant produces a signed id_token when openid scope is present", %{
      conn: conn,
      application: application,
      user: user,
      organization: organization
    } do
      {:ok, auth_code} =
        Authify.OAuth.create_authorization_code(
          application,
          user,
          "https://example.com/callback",
          ["openid", "profile"]
        )

      {:ok, result} = Authify.OAuth.exchange_authorization_code(auth_code, application)
      refresh_token = result.refresh_token

      params = %{
        "grant_type" => "refresh_token",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret,
        "refresh_token" => refresh_token.plaintext_token
      }

      conn = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      response = json_response(conn, 200)

      assert is_binary(response["id_token"])

      segments = String.split(response["id_token"], ".")
      assert length(segments) == 3

      [encoded_header | _] = segments

      header_json =
        encoded_header
        |> Base.url_decode64!(padding: false)
        |> Jason.decode!()

      assert header_json["alg"] == "RS256"
    end

    test "userinfo endpoint returns proper OIDC claims", %{
      conn: conn,
      application: application,
      user: user,
      organization: organization
    } do
      {:ok, auth_code} =
        Authify.OAuth.create_authorization_code(
          application,
          user,
          "https://example.com/callback",
          ["openid", "profile", "email"]
        )

      {:ok, result} = Authify.OAuth.exchange_authorization_code(auth_code, application)
      access_token = result.access_token

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{access_token.token}")
        |> get(~p"/#{organization.slug}/oauth/userinfo")

      response = json_response(conn, 200)

      # Check OIDC-compliant claims
      assert response["sub"] == to_string(user.id)
      assert response["email"] == User.get_primary_email_value(user)
      # Should be present
      assert response["email_verified"]
      # Should be present for profile scope
      assert response["name"]
      # Should map to first_name
      assert response["given_name"]
      # Should map to last_name
      assert response["family_name"]
    end

    @tag :skip
    test "nonce parameter is preserved in ID token", %{
      conn: conn,
      user: user,
      application: application,
      organization: organization
    } do
      conn = log_in_user(conn, user)

      # Include nonce in authorization request
      params = %{
        "client_id" => application.client_id,
        "redirect_uri" => "https://example.com/callback",
        "response_type" => "code",
        "scope" => "openid profile",
        "nonce" => "test_nonce_123"
      }

      conn = get(conn, ~p"/#{organization.slug}/oauth/authorize", params)
      assert html_response(conn, 200) =~ "Authorize Application"

      # Approve consent
      consent_params = %{
        "client_id" => application.client_id,
        "redirect_uri" => "https://example.com/callback",
        "scope" => "openid profile",
        "nonce" => "test_nonce_123",
        "approve" => "true"
      }

      conn =
        post(
          build_conn() |> log_in_user(user),
          ~p"/#{organization.slug}/oauth/consent",
          consent_params
        )

      redirect_url = redirected_to(conn)

      # Extract authorization code from redirect
      code = Regex.run(~r/code=([^&]+)/, redirect_url) |> List.last()

      # Exchange for tokens
      token_params = %{
        "grant_type" => "authorization_code",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret,
        "code" => code
      }

      conn = post(build_conn(), ~p"/#{organization.slug}/oauth/token", token_params)
      response = json_response(conn, 200)

      # Decode ID token and check nonce
      id_token = response["id_token"]
      [_header, payload, _signature] = String.split(id_token, ".")

      payload_json =
        payload
        |> Base.url_decode64!(padding: false)
        |> Jason.decode!()

      assert payload_json["nonce"] == "test_nonce_123"
    end
  end

  describe "OAuth error handling" do
    setup do
      organization = organization_fixture()
      %{organization: organization}
    end

    test "handles malformed requests gracefully", %{conn: conn, organization: organization} do
      # Missing required parameters
      conn = get(conn, ~p"/#{organization.slug}/oauth/authorize")
      assert response(conn, 400)

      # Invalid response_type
      params = %{
        "client_id" => "test_client",
        "redirect_uri" => "https://example.com/callback",
        "response_type" => "invalid_type"
      }

      conn = get(build_conn(), ~p"/#{organization.slug}/oauth/authorize", params)
      assert redirected_to(conn) =~ "https://example.com/callback"
      assert redirected_to(conn) =~ "error=invalid_client"
    end

    test "handles invalid JSON in token requests", %{conn: conn, organization: organization} do
      # Test with malformed JSON - Phoenix should handle this gracefully
      # Note: This might raise ParseError depending on Phoenix configuration
      try do
        conn =
          conn
          |> put_req_header("content-type", "application/json")
          |> post(~p"/#{organization.slug}/oauth/token", "invalid json")

        assert response(conn, 400)
      catch
        # Phoenix may raise ParseError for malformed JSON
        :error, %Plug.Parsers.ParseError{} ->
          # This is acceptable behavior for malformed JSON
          assert true
      end
    end

    @tag :skip
    test "rate limiting for OAuth token endpoint", %{conn: conn, organization: organization} do
      # Skipped: OAuth token endpoint needs rate limiting configured.
      # See: https://github.com/authify/authify/issues/2
      for _i <- 1..20 do
        post(conn, ~p"/#{organization.slug}/oauth/token", %{})
      end

      conn = post(conn, ~p"/#{organization.slug}/oauth/token", %{})
      assert response(conn, 429)
    end
  end

  describe "OAuth authorization with grants" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      application = application_fixture(organization: organization)

      %{organization: organization, user: user, application: application}
    end

    test "auto-approves when user has existing grant with matching scopes", %{
      conn: conn,
      user: user,
      application: application,
      organization: organization
    } do
      # First, create a grant by approving consent
      {:ok, _grant} =
        Authify.OAuth.create_or_update_user_grant(user, application, ["openid", "profile"])

      # Now try to authorize again
      conn = log_in_user(conn, user)

      params = %{
        "client_id" => application.client_id,
        "redirect_uri" => "https://example.com/callback",
        "response_type" => "code",
        "scope" => "openid profile"
      }

      conn = get(conn, ~p"/#{organization.slug}/oauth/authorize", params)

      # Should redirect immediately with authorization code (no consent screen)
      assert redirected_to(conn) =~ "https://example.com/callback"
      assert redirected_to(conn) =~ "code="
      refute html_response(conn, 302) =~ "Authorize Application"
    end

    test "auto-approves when user granted more scopes than requested", %{
      conn: conn,
      user: user,
      application: application,
      organization: organization
    } do
      # Create grant with more scopes
      {:ok, _grant} =
        Authify.OAuth.create_or_update_user_grant(user, application, [
          "openid",
          "profile",
          "email",
          "groups"
        ])

      # Request subset of scopes
      conn = log_in_user(conn, user)

      params = %{
        "client_id" => application.client_id,
        "redirect_uri" => "https://example.com/callback",
        "response_type" => "code",
        "scope" => "openid profile"
      }

      conn = get(conn, ~p"/#{organization.slug}/oauth/authorize", params)

      # Should auto-approve
      assert redirected_to(conn) =~ "https://example.com/callback"
      assert redirected_to(conn) =~ "code="
    end

    test "shows consent when user has no grant", %{
      conn: conn,
      user: user,
      application: application,
      organization: organization
    } do
      conn = log_in_user(conn, user)

      params = %{
        "client_id" => application.client_id,
        "redirect_uri" => "https://example.com/callback",
        "response_type" => "code",
        "scope" => "openid profile"
      }

      conn = get(conn, ~p"/#{organization.slug}/oauth/authorize", params)

      # Should show consent screen
      assert html_response(conn, 200) =~ "Authorize Application"
      assert html_response(conn, 200) =~ application.name
    end

    test "shows consent when user has grant but insufficient scopes", %{
      conn: conn,
      user: user,
      application: application,
      organization: organization
    } do
      # Grant only "openid"
      {:ok, _grant} = Authify.OAuth.create_or_update_user_grant(user, application, ["openid"])

      # Request more scopes
      conn = log_in_user(conn, user)

      params = %{
        "client_id" => application.client_id,
        "redirect_uri" => "https://example.com/callback",
        "response_type" => "code",
        "scope" => "openid profile email"
      }

      conn = get(conn, ~p"/#{organization.slug}/oauth/authorize", params)

      # Should show consent screen for new scopes
      assert html_response(conn, 200) =~ "Authorize Application"
    end

    test "forces consent when prompt=consent parameter present", %{
      conn: conn,
      user: user,
      application: application,
      organization: organization
    } do
      # Create grant
      {:ok, _grant} =
        Authify.OAuth.create_or_update_user_grant(user, application, ["openid", "profile"])

      # Request with prompt=consent
      conn = log_in_user(conn, user)

      params = %{
        "client_id" => application.client_id,
        "redirect_uri" => "https://example.com/callback",
        "response_type" => "code",
        "scope" => "openid profile",
        "prompt" => "consent"
      }

      conn = get(conn, ~p"/#{organization.slug}/oauth/authorize", params)

      # Should show consent screen despite having grant
      assert html_response(conn, 200) =~ "Authorize Application"
    end

    test "returns error when prompt=none and no grant exists", %{
      conn: conn,
      user: user,
      application: application,
      organization: organization
    } do
      conn = log_in_user(conn, user)

      params = %{
        "client_id" => application.client_id,
        "redirect_uri" => "https://example.com/callback",
        "response_type" => "code",
        "scope" => "openid profile",
        "prompt" => "none"
      }

      conn = get(conn, ~p"/#{organization.slug}/oauth/authorize", params)

      # Should redirect with error
      assert redirected_to(conn) =~ "https://example.com/callback"
      assert redirected_to(conn) =~ "error=consent_required"
    end

    test "creates grant when user approves consent", %{
      conn: conn,
      user: user,
      application: application,
      organization: organization
    } do
      # No grant exists initially
      assert is_nil(Authify.OAuth.get_user_grant(user, application))

      conn = log_in_user(conn, user)

      # Approve consent
      params = %{
        "client_id" => application.client_id,
        "redirect_uri" => "https://example.com/callback",
        "scope" => "openid profile email",
        "approve" => "true"
      }

      conn = post(conn, ~p"/#{organization.slug}/oauth/consent", params)

      # Grant should now exist
      grant = Authify.OAuth.get_user_grant(user, application)
      assert grant
      assert grant.scopes == "openid profile email"
      assert is_nil(grant.revoked_at)

      # Authorization should succeed
      assert redirected_to(conn) =~ "https://example.com/callback"
      assert redirected_to(conn) =~ "code="
    end

    test "updates grant scopes when user approves with different scopes", %{
      conn: conn,
      user: user,
      application: application,
      organization: organization
    } do
      # Create initial grant with limited scopes
      {:ok, grant} =
        Authify.OAuth.create_or_update_user_grant(user, application, ["openid"])

      conn = log_in_user(conn, user)

      # Approve with more scopes
      params = %{
        "client_id" => application.client_id,
        "redirect_uri" => "https://example.com/callback",
        "scope" => "openid profile email",
        "approve" => "true"
      }

      conn = post(conn, ~p"/#{organization.slug}/oauth/consent", params)

      # Grant should be updated
      updated_grant = Authify.OAuth.get_user_grant(user, application)
      assert updated_grant.id == grant.id
      assert updated_grant.scopes == "openid profile email"

      # Authorization should succeed
      assert redirected_to(conn) =~ "https://example.com/callback"
    end

    test "un-revokes grant when user re-approves after revocation", %{
      conn: conn,
      user: user,
      application: application,
      organization: organization
    } do
      # Create and revoke grant
      {:ok, grant} =
        Authify.OAuth.create_or_update_user_grant(user, application, ["openid"])

      {:ok, _revoked} = Authify.OAuth.revoke_user_grant(grant)

      # Grant should be revoked
      assert is_nil(Authify.OAuth.get_user_grant(user, application))

      # Approve consent again
      conn = log_in_user(conn, user)

      params = %{
        "client_id" => application.client_id,
        "redirect_uri" => "https://example.com/callback",
        "scope" => "openid profile",
        "approve" => "true"
      }

      conn = post(conn, ~p"/#{organization.slug}/oauth/consent", params)

      # Grant should be un-revoked
      renewed_grant = Authify.OAuth.get_user_grant(user, application)
      assert renewed_grant
      assert renewed_grant.id == grant.id
      assert is_nil(renewed_grant.revoked_at)

      # Authorization should succeed
      assert redirected_to(conn) =~ "https://example.com/callback"
    end
  end
end
