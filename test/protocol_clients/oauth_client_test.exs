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
