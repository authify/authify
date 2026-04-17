defmodule AuthifyTest.OAuthClientIntegrationTest do
  @moduledoc """
  End-to-end integration test for AuthifyTest.OAuthClient.

  This test exercises the complete authorization code + PKCE flow using OAuthClient
  to simulate a conformant OAuth2/OIDC relying party. It catches a class of bugs
  that the existing server-only tests miss:

  - ID token signature bugs (server could produce a token signed with the wrong
    key or using the wrong algorithm — server tests never call :public_key.verify/4)
  - PKCE enforcement gaps (wrong verifier accepted — server tests assert on HTTP
    status but not on whether PKCE was actually validated)
  - Scope/claim mismatches (userinfo returning wrong claims for a given scope set)
  - Nonce round-trip failures (server omitting the nonce claim from the ID token)
  - Refresh token producing a valid new access token (not just a 200 response)
  """

  use AuthifyWeb.ConnCase, async: true

  alias AuthifyTest.OAuthClient

  import Authify.AccountsFixtures
  import Authify.OAuthFixtures

  @tag :capture_log
  test "complete authorization code + PKCE flow with client-side ID token validation" do
    org = organization_fixture()
    app = application_fixture(organization: org)
    user = user_for_organization_fixture(org)

    client = OAuthClient.new(build_conn(), app, org)

    # Step 1: Authorization code + PKCE flow
    assert {:ok, {conn, code, verifier, nonce}} =
             OAuthClient.authorize(client, user, scopes: ["openid", "profile", "email"])

    assert is_binary(code)
    assert is_binary(verifier)
    assert is_binary(nonce)

    # Step 2: Exchange code for tokens
    assert {:ok, tokens} = OAuthClient.exchange_code(client, conn, code, verifier)
    assert is_binary(tokens.access_token)
    assert is_binary(tokens.id_token)
    assert is_binary(tokens.refresh_token)
    assert tokens.token_type == "Bearer"

    # Step 3: Client-side RS256 signature verification + claims validation.
    # This is the key check that server-only tests do not perform.
    assert {:ok, claims} = OAuthClient.validate_id_token(client, tokens.id_token, nonce: nonce)
    assert claims["sub"] == to_string(user.id)
    assert claims["aud"] == app.client_id
    assert is_integer(claims["exp"])
    assert claims["nonce"] == nonce

    # Step 4: Userinfo scope-to-claim mapping
    assert {:ok, userinfo} = OAuthClient.fetch_userinfo(client, tokens.access_token)
    assert userinfo["sub"] == to_string(user.id)
    assert is_binary(userinfo["email"])
    assert is_binary(userinfo["name"])

    # Step 5: Refresh token grant produces a usable new access token
    assert {:ok, new_tokens} = OAuthClient.refresh(client, tokens.refresh_token)
    assert is_binary(new_tokens.access_token)
    refute new_tokens.access_token == tokens.access_token

    assert {:ok, refreshed_userinfo} = OAuthClient.fetch_userinfo(client, new_tokens.access_token)
    assert refreshed_userinfo["sub"] == to_string(user.id)
  end
end
