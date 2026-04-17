defmodule AuthifyTest.OAuthClientTest do
  @moduledoc false

  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures
  import Authify.OAuthFixtures

  alias AuthifyTest.OAuthClient

  describe "generate_pkce/0" do
    test "challenge is SHA-256 of verifier, base64url-encoded without padding" do
      {verifier, challenge} = OAuthClient.generate_pkce()

      expected_challenge =
        :crypto.hash(:sha256, verifier) |> Base.url_encode64(padding: false)

      assert challenge == expected_challenge
      assert byte_size(verifier) > 0
      assert byte_size(challenge) > 0
      # No padding characters
      refute String.contains?(verifier, "=")
      refute String.contains?(challenge, "=")
    end

    test "generates unique verifiers on each call" do
      {v1, _} = OAuthClient.generate_pkce()
      {v2, _} = OAuthClient.generate_pkce()
      refute v1 == v2
    end
  end

  describe "authorize/3" do
    setup do
      org = organization_fixture()
      app = application_fixture(organization: org)
      user = user_for_organization_fixture(org)
      %{org: org, app: app, user: user}
    end

    test "returns code, verifier, and nonce for a fresh user (consent required)", %{
      org: org,
      app: app,
      user: user
    } do
      client = OAuthClient.new(build_conn(), app, org)

      assert {:ok, {_conn, code, verifier, nonce}} =
               OAuthClient.authorize(client, user, scopes: ["openid", "profile", "email"])

      assert is_binary(code) and byte_size(code) > 0
      assert is_binary(verifier) and byte_size(verifier) > 0
      assert is_binary(nonce) and byte_size(nonce) > 0
    end

    test "generates a unique nonce on each call", %{org: org, app: app, user: user} do
      client = OAuthClient.new(build_conn(), app, org)
      {:ok, {_, _, _, nonce1}} = OAuthClient.authorize(client, user, scopes: ["openid"])
      {:ok, {_, _, _, nonce2}} = OAuthClient.authorize(client, user, scopes: ["openid"])
      refute nonce1 == nonce2
    end
  end

  describe "validate_id_token/3" do
    setup do
      org = organization_fixture()
      app = application_fixture(organization: org)
      user = user_for_organization_fixture(org)
      client = OAuthClient.new(build_conn(), app, org)

      {:ok, {conn, code, verifier, nonce}} =
        OAuthClient.authorize(client, user, scopes: ["openid", "profile", "email"])

      {:ok, tokens} = OAuthClient.exchange_code(client, conn, code, verifier)

      %{org: org, app: app, user: user, client: client, tokens: tokens, nonce: nonce}
    end

    test "accepts a valid RS256-signed ID token", %{client: client, tokens: tokens, nonce: nonce} do
      assert {:ok, claims} = OAuthClient.validate_id_token(client, tokens.id_token, nonce: nonce)
      assert is_map(claims)
      assert is_binary(claims["sub"])
      assert is_binary(claims["iss"])
    end

    test "rejects a tampered signature", %{client: client, tokens: tokens, nonce: nonce} do
      [header, payload, _sig] = String.split(tokens.id_token, ".")
      tampered = "#{header}.#{payload}.dGFtcGVyZWQ"

      assert {:error, :invalid_signature} =
               OAuthClient.validate_id_token(client, tampered, nonce: nonce)
    end

    test "rejects an expired token", %{org: org, app: app, client: client} do
      # Sign a token with an exp in the past using the org's actual signing key
      {:ok, cert} = Authify.Accounts.get_or_generate_oauth_signing_certificate(org)
      [entry | _] = :public_key.pem_decode(cert.private_key)
      private_key = :public_key.pem_entry_decode(entry)

      now = System.system_time(:second)

      claims = %{
        "iss" => "#{AuthifyWeb.Endpoint.url()}/#{org.slug}",
        "sub" => "1",
        "aud" => app.client_id,
        "exp" => now - 3600,
        "iat" => now - 7200
      }

      header = %{"alg" => "RS256", "typ" => "JWT", "kid" => to_string(cert.id)}
      encoded_header = Base.url_encode64(Jason.encode!(header), padding: false)
      encoded_claims = Base.url_encode64(Jason.encode!(claims), padding: false)
      signing_input = "#{encoded_header}.#{encoded_claims}"
      signature = :public_key.sign(signing_input, :sha256, private_key)
      expired_token = "#{signing_input}.#{Base.url_encode64(signature, padding: false)}"

      assert {:error, :expired} = OAuthClient.validate_id_token(client, expired_token)
    end

    test "rejects wrong audience", %{org: org, tokens: tokens, nonce: nonce} do
      # Create a second app; its client_id won't match the token's aud claim
      app2 = application_fixture(organization: org)
      client2 = OAuthClient.new(build_conn(), app2, org)

      assert {:error, :wrong_audience} =
               OAuthClient.validate_id_token(client2, tokens.id_token, nonce: nonce)
    end

    test "rejects nonce mismatch", %{client: client, tokens: tokens} do
      assert {:error, :nonce_mismatch} =
               OAuthClient.validate_id_token(client, tokens.id_token,
                 nonce: "definitely-wrong-nonce"
               )
    end
  end

  describe "fetch_userinfo/2" do
    setup do
      org = organization_fixture()
      app = application_fixture(organization: org)
      user = user_for_organization_fixture(org)
      client = OAuthClient.new(build_conn(), app, org)
      %{org: org, app: app, user: user, client: client}
    end

    test "returns claims when email scope is requested", %{client: client, user: user} do
      {:ok, {conn, code, verifier, _nonce}} =
        OAuthClient.authorize(client, user, scopes: ["openid", "profile", "email"])

      {:ok, tokens} = OAuthClient.exchange_code(client, conn, code, verifier)

      assert {:ok, userinfo} = OAuthClient.fetch_userinfo(client, tokens.access_token)
      assert is_binary(userinfo["sub"])
      assert is_binary(userinfo["email"])
      assert is_binary(userinfo["name"])
    end

    test "email claim is absent when email scope is not requested", %{client: client, user: user} do
      {:ok, {conn, code, verifier, _nonce}} =
        OAuthClient.authorize(client, user, scopes: ["openid", "profile"])

      {:ok, tokens} = OAuthClient.exchange_code(client, conn, code, verifier)

      assert {:ok, userinfo} = OAuthClient.fetch_userinfo(client, tokens.access_token)
      assert is_binary(userinfo["sub"])
      refute Map.has_key?(userinfo, "email")
    end

    test "returns error for invalid access token", %{client: client} do
      assert {:error, _reason} = OAuthClient.fetch_userinfo(client, "not-a-valid-token")
    end
  end

  describe "refresh/2" do
    setup do
      org = organization_fixture()
      app = application_fixture(organization: org)
      user = user_for_organization_fixture(org)
      client = OAuthClient.new(build_conn(), app, org)

      {:ok, {conn, code, verifier, _nonce}} =
        OAuthClient.authorize(client, user, scopes: ["openid", "profile"])

      {:ok, tokens} = OAuthClient.exchange_code(client, conn, code, verifier)

      %{client: client, tokens: tokens}
    end

    test "returns a new access token", %{client: client, tokens: tokens} do
      assert {:ok, new_tokens} = OAuthClient.refresh(client, tokens.refresh_token)
      assert is_binary(new_tokens.access_token)
      assert new_tokens.token_type == "Bearer"
      assert is_integer(new_tokens.expires_in)
    end

    test "new access token differs from the original", %{client: client, tokens: tokens} do
      {:ok, new_tokens} = OAuthClient.refresh(client, tokens.refresh_token)
      refute new_tokens.access_token == tokens.access_token
    end

    test "returns error for invalid refresh token", %{client: client} do
      assert {:error, _reason} = OAuthClient.refresh(client, "not-a-valid-refresh-token")
    end
  end

  describe "client_credentials/2" do
    setup do
      org = organization_fixture()
      # Management API app required for client_credentials grant
      app = management_api_application_fixture(organization: org)
      client = OAuthClient.new(build_conn(), app, org)
      %{org: org, app: app, client: client}
    end

    test "returns an access token with correct shape", %{client: client} do
      assert {:ok, tokens} =
               OAuthClient.client_credentials(client,
                 scopes: ["management_app:read", "users:read"]
               )

      assert is_binary(tokens.access_token)
      assert tokens.token_type == "Bearer"
      assert is_integer(tokens.expires_in)
    end

    test "returns error for scopes not granted to the app", %{client: client} do
      result = OAuthClient.client_credentials(client, scopes: ["invalid_scope"])
      assert match?({:error, _}, result)
    end
  end

  describe "exchange_code/4" do
    setup do
      org = organization_fixture()
      app = application_fixture(organization: org)
      user = user_for_organization_fixture(org)
      client = OAuthClient.new(build_conn(), app, org)

      {:ok, {conn, code, verifier, nonce}} =
        OAuthClient.authorize(client, user, scopes: ["openid", "profile", "email"])

      %{
        org: org,
        app: app,
        user: user,
        client: client,
        conn: conn,
        code: code,
        verifier: verifier,
        nonce: nonce
      }
    end

    test "returns tokens map with all required fields", %{
      client: client,
      conn: conn,
      code: code,
      verifier: verifier
    } do
      assert {:ok, tokens} = OAuthClient.exchange_code(client, conn, code, verifier)
      assert is_binary(tokens.access_token)
      assert is_binary(tokens.id_token)
      assert is_binary(tokens.refresh_token)
      assert is_integer(tokens.expires_in)
      assert tokens.token_type == "Bearer"
    end

    test "server rejects wrong code_verifier", %{client: client, conn: conn, code: code} do
      wrong_verifier = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
      assert {:error, _reason} = OAuthClient.exchange_code(client, conn, code, wrong_verifier)
    end
  end
end
