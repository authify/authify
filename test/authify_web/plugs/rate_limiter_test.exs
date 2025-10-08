defmodule AuthifyWeb.Plugs.RateLimiterTest do
  use AuthifyWeb.ConnCase, async: false
  import Authify.RateLimitTestHelper

  alias AuthifyWeb.Plugs.RateLimiter
  alias Authify.AccountsFixtures

  describe "rate limiting (when enabled)" do
    setup do
      # Enable rate limiting for this test module
      enable_rate_limiting()

      # Create a test organization and user for authenticated tests
      org = AccountsFixtures.organization_fixture()
      user = AccountsFixtures.user_fixture(%{organization: org})

      {:ok, org: org, user: user}
    end

    test "auth_rate_limit blocks excessive requests", %{conn: _conn} do
      # Clear any existing rate limits
      clear_rate_limits()

      # First 10 requests should succeed
      for _ <- 1..10 do
        conn = build_conn() |> RateLimiter.auth_rate_limit()
        refute conn.halted
      end

      # 11th request should be rate limited
      conn = build_conn() |> RateLimiter.auth_rate_limit()
      assert conn.halted
      assert conn.status == 429
      assert get_resp_header(conn, "retry-after") != []
    end

    test "oauth_rate_limit has higher limit", %{conn: _conn} do
      # Clear any existing rate limits
      clear_rate_limits()

      # First 60 requests should succeed
      for _ <- 1..60 do
        conn = build_conn() |> RateLimiter.oauth_rate_limit()
        refute conn.halted
      end

      # 61st request should be rate limited
      conn = build_conn() |> RateLimiter.oauth_rate_limit()
      assert conn.halted
      assert conn.status == 429
    end

    test "saml_rate_limit blocks after limit", %{conn: _conn} do
      # Clear any existing rate limits
      clear_rate_limits()

      # First 30 requests should succeed
      for _ <- 1..30 do
        conn = build_conn() |> RateLimiter.saml_rate_limit()
        refute conn.halted
      end

      # 31st request should be rate limited
      conn = build_conn() |> RateLimiter.saml_rate_limit()
      assert conn.halted
      assert conn.status == 429
    end

    test "api_rate_limit blocks after limit", %{user: user} do
      # Clear any existing rate limits
      clear_rate_limits()

      # First 100 requests should succeed
      for _ <- 1..100 do
        conn = build_conn() |> Authify.Guardian.Plug.sign_in(user) |> RateLimiter.api_rate_limit()
        refute conn.halted
      end

      # 101st request should be rate limited
      conn = build_conn() |> Authify.Guardian.Plug.sign_in(user) |> RateLimiter.api_rate_limit()
      assert conn.halted
      assert conn.status == 429
    end

    test "custom rate_limit respects provided options", %{conn: _conn} do
      # Clear any existing rate limits
      clear_rate_limits()

      # Set custom low limit for testing
      opts = [scale_ms: 60_000, limit: 3, scope: "custom"]

      # First 3 requests should succeed
      for _ <- 1..3 do
        conn = build_conn() |> RateLimiter.rate_limit(opts)
        refute conn.halted
      end

      # 4th request should be rate limited
      conn = build_conn() |> RateLimiter.rate_limit(opts)
      assert conn.halted
      assert conn.status == 429
    end

    test "rate limit response format matches content type", %{conn: _conn} do
      # Clear any existing rate limits
      clear_rate_limits()

      # Exhaust the rate limit
      for _ <- 1..10 do
        build_conn() |> RateLimiter.auth_rate_limit()
      end

      # Test JSON response
      conn =
        build_conn()
        |> put_req_header("accept", "application/json")
        |> RateLimiter.auth_rate_limit()

      assert conn.halted
      assert conn.status == 429
      assert get_resp_header(conn, "content-type") |> List.first() =~ "application/json"
      response = Jason.decode!(conn.resp_body)
      assert response["error"] =~ "Rate limit exceeded"

      # Clear for next test
      clear_rate_limits()

      # Exhaust again
      for _ <- 1..10 do
        build_conn() |> RateLimiter.auth_rate_limit()
      end

      # Test HTML response
      conn =
        build_conn()
        |> put_req_header("accept", "text/html")
        |> RateLimiter.auth_rate_limit()

      assert conn.halted
      assert conn.status == 429
      assert get_resp_header(conn, "content-type") |> List.first() =~ "text/html"
      assert conn.resp_body =~ "Too Many Requests"
      assert conn.resp_body =~ "429"
    end

    test "different scopes have independent rate limits", %{conn: _conn} do
      # Clear any existing rate limits from previous tests
      clear_rate_limits()

      # Exhaust auth rate limit (10 requests)
      for _ <- 1..10 do
        conn = build_conn() |> RateLimiter.auth_rate_limit()
        refute conn.halted
      end

      # 11th auth request should be blocked
      conn = build_conn() |> RateLimiter.auth_rate_limit()
      assert conn.halted

      # But OAuth should still work (different scope)
      conn = build_conn() |> RateLimiter.oauth_rate_limit()
      refute conn.halted, "OAuth should not be rate limited when auth is exhausted"

      # SAML should still work (different scope)
      conn = build_conn() |> RateLimiter.saml_rate_limit()
      refute conn.halted, "SAML should not be rate limited when auth is exhausted"

      # API should still work (different scope)
      conn = build_conn() |> RateLimiter.api_rate_limit()
      refute conn.halted, "API should not be rate limited when auth is exhausted"
    end
  end

  describe "rate limiting (when disabled)" do
    test "allows unlimited requests when disabled", %{conn: _conn} do
      # Ensure rate limiting is disabled (default in tests)
      disable_rate_limiting()

      # Should be able to make many more requests than the limit
      for _ <- 1..100 do
        conn = build_conn() |> RateLimiter.auth_rate_limit()
        refute conn.halted
      end
    end
  end
end
