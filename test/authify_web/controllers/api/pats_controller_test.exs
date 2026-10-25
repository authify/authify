defmodule AuthifyWeb.API.PatsControllerTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  alias Authify.AuditLog
  alias Authify.PersonalAccessTokens

  defp authenticate_with_pat(conn, user, scopes, name \\ "API Client Token") do
    organization = user.organization

    {:ok, token} =
      PersonalAccessTokens.create_personal_access_token(user, organization, %{
        "name" => name,
        "scopes" => scopes
      })

    conn
    |> put_req_header("accept", "application/vnd.authify.v1+json")
    |> put_req_header("content-type", "application/vnd.authify.v1+json")
    |> put_req_header("authorization", "Bearer #{token.plaintext_token}")
  end

  defp create_token(user, scopes, name) do
    {:ok, token} =
      PersonalAccessTokens.create_personal_access_token(user, user.organization, %{
        "name" => name,
        "scopes" => scopes
      })

    Authify.Repo.preload(token, :scopes)
  end

  defp authenticate_as_application(conn, organization, scopes) do
    conn
    |> put_req_header("accept", "application/vnd.authify.v1+json")
    |> put_req_header("content-type", "application/vnd.authify.v1+json")
    |> assign(:api_authenticated, true)
    |> assign(:current_user, %{
      id: nil,
      email: "automation@example.com",
      service_account: true
    })
    |> assign(:current_organization, organization)
    |> assign(:current_scopes, scopes)
    |> assign(:actor_type, :application)
    |> assign(:current_application, %{id: 1, name: "Automation App"})
  end

  # Authenticates a request with a token the caller already made, so the test
  # can use that exact token.
  defp authenticate_with_named_pat(conn, token) do
    conn
    |> put_req_header("accept", "application/vnd.authify.v1+json")
    |> put_req_header("authorization", "Bearer #{token.plaintext_token}")
  end

  # Simulates a non-PAT caller, such as a web session or a JWT, matching how the
  # other API controller tests authenticate a user. APIAuth short-circuits on
  # :api_authenticated in test, and the caller carries no :current_pat_id, so
  # the self-revocation guard must not block it.
  defp authenticate_as_non_pat(conn, user, scopes) do
    organization = user.organization

    conn
    |> put_req_header("accept", "application/vnd.authify.v1+json")
    |> put_req_header("content-type", "application/vnd.authify.v1+json")
    |> log_in_user(user)
    |> assign(:current_user, user)
    |> assign(:current_organization, organization)
    |> assign(:api_authenticated, true)
    |> assign(:current_scopes, scopes)
  end

  defp future_timestamp do
    DateTime.utc_now()
    |> DateTime.add(30, :day)
    |> DateTime.truncate(:second)
    |> DateTime.to_iso8601()
  end

  describe "POST /api/pats" do
    test "creates a token for the current user and returns it exactly once", %{conn: conn} do
      user = user_fixture()
      organization = user.organization
      conn = authenticate_with_pat(conn, user, ["profile:read", "profile:write"])

      response =
        conn
        |> post("/#{organization.slug}/api/pats", %{
          "personal_access_token" => %{
            "name" => "CI Token",
            "description" => "Used by the smoke suite",
            "scopes" => ["profile:read", "profile:write"],
            "expires_at" => future_timestamp()
          }
        })
        |> json_response(201)

      token_id = response["data"]["id"]
      attributes = response["data"]["attributes"]

      assert response["data"]["type"] == "personal_access_token"
      assert response["data"]["links"]["self"] == "/#{organization.slug}/api/pats/#{token_id}"
      assert attributes["name"] == "CI Token"
      assert attributes["description"] == "Used by the smoke suite"
      assert Enum.sort(attributes["scopes"]) == ["profile:read", "profile:write"]
      assert attributes["user_id"] == user.id
      assert attributes["organization_id"] == organization.id
      assert String.starts_with?(attributes["token"], "authify_pat_")
      assert attributes["expires_at"]
      refute Map.has_key?(attributes, "token_hash")

      # The stored token is the hash, not the plaintext value
      [stored] =
        PersonalAccessTokens.list_personal_access_tokens_in_organization(organization,
          user_id: user.id
        )
        |> Enum.filter(&(&1.name == "CI Token"))

      refute stored.token == attributes["token"]
      assert stored.token == Authify.Accounts.PersonalAccessToken.hash_token(attributes["token"])

      # Listing never returns the token value again
      list_response =
        conn
        |> get("/#{organization.slug}/api/pats")
        |> json_response(200)

      [listed] = Enum.filter(list_response["data"], &(&1["id"] == token_id))
      refute Map.has_key?(listed["attributes"], "token")

      # The newly minted token authenticates successfully
      new_conn =
        build_conn()
        |> put_req_header("accept", "application/vnd.authify.v1+json")
        |> put_req_header("authorization", "Bearer #{attributes["token"]}")

      assert %{"data" => %{"type" => "user"}} =
               new_conn
               |> get("/#{organization.slug}/api/profile")
               |> json_response(200)

      [event] =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "personal_access_token_created"
        )

      assert event.metadata["source"] == "api"
      assert event.metadata["personal_access_token_id"] == String.to_integer(token_id)
      assert Enum.sort(event.metadata["scopes"]) == ["profile:read", "profile:write"]
    end

    test "allows profile:write to mint profile:read", %{conn: conn} do
      user = user_fixture()
      organization = user.organization
      conn = authenticate_with_pat(conn, user, ["profile:write"])

      response =
        conn
        |> post("/#{organization.slug}/api/pats", %{
          "personal_access_token" => %{
            "name" => "Read Only",
            "scopes" => ["profile:read"]
          }
        })
        |> json_response(201)

      assert response["data"]["attributes"]["scopes"] == ["profile:read"]
    end

    test "rejects scopes that the authenticating token does not hold", %{conn: conn} do
      user = user_fixture()
      organization = user.organization
      conn = authenticate_with_pat(conn, user, ["profile:write"])

      response =
        conn
        |> post("/#{organization.slug}/api/pats", %{
          "personal_access_token" => %{
            "name" => "Escalated Token",
            "scopes" => ["users:write"]
          }
        })
        |> json_response(403)

      assert response["error"]["type"] == "insufficient_scope"
      assert response["error"]["details"]["requested"] == ["users:write"]
      assert response["error"]["details"]["provided"] == ["profile:write"]
    end

    test "returns validation errors for invalid scopes", %{conn: conn} do
      user = user_fixture()
      organization = user.organization
      conn = authenticate_with_pat(conn, user, ["profile:write"])

      response =
        conn
        |> post("/#{organization.slug}/api/pats", %{
          "personal_access_token" => %{
            "name" => "Invalid",
            "scopes" => ["not:a:scope"]
          }
        })
        |> json_response(422)

      assert response["error"]["type"] == "validation_failed"
      assert response["error"]["details"]["scopes"]
    end

    test "requires personal_access_token parameters", %{conn: conn} do
      user = user_fixture()
      organization = user.organization
      conn = authenticate_with_pat(conn, user, ["profile:write"])

      response =
        conn
        |> post("/#{organization.slug}/api/pats", %{})
        |> json_response(400)

      assert response["error"]["type"] == "invalid_request"
    end

    test "an admin cannot create a token for another user", %{conn: conn} do
      organization = organization_fixture()
      admin = user_fixture(organization: organization, role: "admin")
      target = user_fixture(organization: organization)

      # Even with both the self-service and admin scopes, create is self-only.
      conn =
        authenticate_with_pat(conn, admin, [
          "profile:read",
          "profile:write",
          "users:read",
          "users:write"
        ])

      response =
        conn
        |> post("/#{organization.slug}/api/pats", %{
          "personal_access_token" => %{
            "name" => "Admin Minted Token",
            "scopes" => ["profile:read", "profile:write"],
            "user_id" => target.id
          }
        })
        |> json_response(403)

      assert response["error"]["type"] == "insufficient_permissions"
      assert response["error"]["message"] =~ "authenticated user"

      assert PersonalAccessTokens.list_personal_access_tokens(target) == []
    end

    test "application credentials cannot create personal access tokens", %{conn: conn} do
      organization = organization_fixture()

      conn =
        authenticate_as_application(conn, organization, [
          "profile:read",
          "profile:write",
          "users:read",
          "users:write"
        ])

      response =
        conn
        |> post("/#{organization.slug}/api/pats", %{
          "personal_access_token" => %{
            "name" => "Application Token",
            "scopes" => ["profile:read"]
          }
        })
        |> json_response(403)

      assert response["error"]["type"] == "insufficient_permissions"
      assert response["error"]["message"] =~ "Application credentials"
    end

    test "rejects user_id even when it matches the authenticated user", %{conn: conn} do
      user = user_fixture()
      organization = user.organization
      conn = authenticate_with_pat(conn, user, ["profile:write"])

      response =
        conn
        |> post("/#{organization.slug}/api/pats", %{
          "personal_access_token" => %{
            "name" => "Self With user_id",
            "scopes" => ["profile:read"],
            "user_id" => user.id
          }
        })
        |> json_response(403)

      assert response["error"]["type"] == "insufficient_permissions"
    end
  end

  describe "GET /api/pats" do
    test "lists only the current user's tokens and never returns token values", %{conn: conn} do
      organization = organization_fixture()
      user = user_fixture(organization: organization)
      other_user = user_fixture(organization: organization)

      create_token(user, ["profile:read"], "Mine")
      create_token(other_user, ["profile:read"], "Theirs")

      conn = authenticate_with_pat(conn, user, ["profile:read"])

      response =
        conn
        |> get("/#{organization.slug}/api/pats")
        |> json_response(200)

      names = Enum.map(response["data"], & &1["attributes"]["name"])

      assert "Mine" in names
      assert "API Client Token" in names
      refute "Theirs" in names

      assert Enum.all?(response["data"], fn token ->
               not Map.has_key?(token["attributes"], "token")
             end)
    end

    test "allows an admin to list another user's tokens with user_id", %{conn: conn} do
      organization = organization_fixture()
      admin = user_fixture(organization: organization, role: "admin")
      target = user_fixture(organization: organization)
      target_token = create_token(target, ["profile:read"], "Target Token")

      conn = authenticate_with_pat(conn, admin, ["users:read"])

      response =
        conn
        |> get("/#{organization.slug}/api/pats?user_id=#{target.id}")
        |> json_response(200)

      assert [token] = response["data"]
      assert token["id"] == to_string(target_token.id)
      assert token["attributes"]["user_id"] == target.id
      refute Map.has_key?(token["attributes"], "token")
    end

    test "a non-admin cannot list another user's tokens", %{conn: conn} do
      organization = organization_fixture()
      actor = user_fixture(organization: organization, role: "user")
      target = user_fixture(organization: organization)
      create_token(target, ["profile:read"], "Target Token")

      conn = authenticate_with_pat(conn, actor, ["users:read"])

      response =
        conn
        |> get("/#{organization.slug}/api/pats?user_id=#{target.id}")
        |> json_response(403)

      assert response["error"]["type"] == "insufficient_permissions"
    end

    test "requires profile:read for self-service listing", %{conn: conn} do
      user = user_fixture()
      organization = user.organization
      conn = authenticate_with_pat(conn, user, ["users:read"])

      response =
        conn
        |> get("/#{organization.slug}/api/pats")
        |> json_response(403)

      assert response["error"]["type"] == "insufficient_scope"
    end
  end

  describe "DELETE /api/pats/:id" do
    test "revokes the current user's token", %{conn: conn} do
      user = user_fixture()
      organization = user.organization
      token = create_token(user, ["profile:read"], "To Revoke")
      conn = authenticate_with_pat(conn, user, ["profile:write"])

      conn = delete(conn, "/#{organization.slug}/api/pats/#{token.id}")
      assert response(conn, 204)

      refute PersonalAccessTokens.get_personal_access_token_in_organization(
               token.id,
               organization
             )

      [event] =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "personal_access_token_deleted"
        )

      assert event.metadata["source"] == "api"
      assert event.metadata["personal_access_token_id"] == token.id
      refute Map.has_key?(event.metadata, "admin_managed")
    end

    test "a user cannot revoke another user's token without admin permissions", %{conn: conn} do
      organization = organization_fixture()
      actor = user_fixture(organization: organization)
      target = user_fixture(organization: organization)
      token = create_token(target, ["profile:read"], "Target Token")
      conn = authenticate_with_pat(conn, actor, ["profile:write"])

      response =
        conn
        |> delete("/#{organization.slug}/api/pats/#{token.id}")
        |> json_response(403)

      assert response["error"]["type"] == "insufficient_scope"

      assert PersonalAccessTokens.get_personal_access_token_in_organization(
               token.id,
               organization
             )
    end

    test "an admin can revoke another user's token", %{conn: conn} do
      organization = organization_fixture()
      admin = user_fixture(organization: organization, role: "admin")
      target = user_fixture(organization: organization)
      token = create_token(target, ["profile:read"], "Target Token")
      conn = authenticate_with_pat(conn, admin, ["users:write"])

      conn = delete(conn, "/#{organization.slug}/api/pats/#{token.id}")
      assert response(conn, 204)

      refute PersonalAccessTokens.get_personal_access_token_in_organization(
               token.id,
               organization
             )

      [event] =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "personal_access_token_deleted"
        )

      assert event.metadata["admin_managed"] == true
      assert event.metadata["user_id"] == target.id
    end

    test "returns 404 for a token outside the organization", %{conn: conn} do
      organization = organization_fixture()
      user = user_fixture(organization: organization)
      other_organization = organization_fixture()
      other_user = user_fixture(organization: other_organization)
      token = create_token(other_user, ["profile:read"], "Elsewhere")
      conn = authenticate_with_pat(conn, user, ["profile:write"])

      response =
        conn
        |> delete("/#{organization.slug}/api/pats/#{token.id}")
        |> json_response(404)

      assert response["error"]["type"] == "resource_not_found"
    end

    test "a personal access token cannot revoke itself", %{conn: conn} do
      user = user_fixture()
      organization = user.organization
      token = create_token(user, ["profile:write"], "Active Token")

      response =
        authenticate_with_named_pat(conn, token)
        |> delete("/#{organization.slug}/api/pats/#{token.id}")
        |> json_response(409)

      assert response["error"]["type"] == "invalid_operation"
      assert response["error"]["message"] =~ "cannot revoke itself"

      # The active token is still present and usable for future requests.
      remaining =
        PersonalAccessTokens.get_personal_access_token_in_organization(
          token.id,
          organization
        )

      assert remaining
      assert remaining.is_active
    end

    test "a personal access token can revoke another of its owners tokens", %{conn: conn} do
      user = user_fixture()
      organization = user.organization
      authenticating = create_token(user, ["profile:write"], "Keep Me")
      target = create_token(user, ["profile:read"], "Take Me Out")

      conn =
        authenticate_with_named_pat(conn, authenticating)
        |> delete("/#{organization.slug}/api/pats/#{target.id}")

      assert response(conn, 204)

      refute PersonalAccessTokens.get_personal_access_token_in_organization(
               target.id,
               organization
             )

      # The credential that made the request is still active.
      assert PersonalAccessTokens.get_personal_access_token_in_organization(
               authenticating.id,
               organization
             )
    end

    test "a session or JWT authed user can revoke their own token", %{conn: conn} do
      user = user_fixture()
      organization = user.organization
      token = create_token(user, ["profile:write"], "Session Revoke")

      conn =
        authenticate_as_non_pat(conn, user, ["profile:write"])
        |> delete("/#{organization.slug}/api/pats/#{token.id}")

      assert response(conn, 204)

      refute PersonalAccessTokens.get_personal_access_token_in_organization(
               token.id,
               organization
             )
    end

    test "an administrator acting by PAT cannot revoke that same PAT", %{conn: conn} do
      organization = organization_fixture()
      admin = user_fixture(organization: organization, role: "admin")

      {:ok, token} =
        PersonalAccessTokens.create_personal_access_token(admin, organization, %{
          "name" => "Admin Active Token",
          "scopes" => ["profile:write", "users:write"]
        })

      response =
        authenticate_with_named_pat(conn, token)
        |> delete("/#{organization.slug}/api/pats/#{token.id}")
        |> json_response(409)

      assert response["error"]["type"] == "invalid_operation"

      assert PersonalAccessTokens.get_personal_access_token_in_organization(
               token.id,
               organization
             )
    end
  end
end
