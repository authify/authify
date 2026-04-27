defmodule AuthifyWeb.OAuthIntegrationTest do
  @moduledoc """
  Integration test demonstrating the IntegrationCase base template.

  Exercises a complete OAuth2 PKCE flow with client-side RS256 ID token
  validation using OAuthClient, which is aliased automatically by
  IntegrationCase.
  """

  use AuthifyWeb.IntegrationCase

  import Authify.OAuthFixtures

  @tag :capture_log
  test "complete PKCE flow with client-side ID token validation", %{
    conn: conn,
    org: org,
    admin: admin
  } do
    app = application_fixture(organization: org)
    client = OAuthClient.new(conn, app, org)

    assert {:ok, {resp_conn, code, verifier, nonce}} =
             OAuthClient.authorize(client, admin, scopes: ["openid", "profile"])

    assert resp_conn.status in [302]

    assert {:ok, tokens} =
             OAuthClient.exchange_code(client, build_conn(), code, verifier)

    assert is_binary(tokens.id_token)
    assert tokens.token_type == "Bearer"

    assert {:ok, claims} = OAuthClient.validate_id_token(client, tokens.id_token, nonce: nonce)
    assert claims["sub"] == to_string(admin.id)
    assert claims["nonce"] == nonce
  end
end
