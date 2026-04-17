defmodule AuthifyTest.OAuthClientTest do
  use AuthifyWeb.ConnCase, async: true

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
end
