defmodule AuthifyWeb.OAuthControllerSyncTest do
  # async: false — the rate limiting tests exercise global Hammer rate limit
  # buckets, which are shared state and would race with concurrent tests.
  use AuthifyWeb.ConnCase, async: false

  import Authify.AccountsFixtures

  describe "rate limiting" do
    setup do
      organization = organization_fixture()
      Authify.RateLimitTestHelper.enable_rate_limiting()
      %{organization: organization}
    end

    test "blocks excessive requests to OAuth token endpoint", %{
      conn: conn,
      organization: organization
    } do
      Authify.RateLimitTestHelper.clear_rate_limits()

      for _i <- 1..60 do
        result = post(conn, ~p"/#{organization.slug}/oauth/token", %{})
        refute result.status == 429
      end

      conn = post(conn, ~p"/#{organization.slug}/oauth/token", %{})
      assert response(conn, 429)
    end

    test "blocks excessive requests to OAuth userinfo endpoint", %{
      conn: conn,
      organization: organization
    } do
      Authify.RateLimitTestHelper.clear_rate_limits()

      for _i <- 1..60 do
        result = get(conn, ~p"/#{organization.slug}/oauth/userinfo")
        refute result.status == 429
      end

      conn = get(conn, ~p"/#{organization.slug}/oauth/userinfo")
      assert response(conn, 429)
    end
  end
end
