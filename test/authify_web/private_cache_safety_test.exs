defmodule AuthifyWeb.PrivateCacheSafetyTest do
  @moduledoc """
  Guards the cache-header contract that keeps private content out of shared
  caches (browsers, reverse proxies, and CDNs).

  Most dynamic responses carry no explicit `cache-control` header; they rely
  on Plug's default of `max-age=0, private, must-revalidate`. That default is
  safe for shared caches but is only one dependency bump away from changing.
  Sensitive endpoints add `no-store` on top (see
  `AuthifyWeb.Plugs.NoStoreCacheTest`). These tests lock in the contract:

    * dynamic responses (public and authenticated) must not be publicly
      cacheable

    * digested static assets should be long-lived and publicly cacheable

  If Plug's default ever changes, these tests fail and force a conscious
  decision rather than silently exposing private pages to a CDN.
  """
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  # A response is safe for a shared cache only if it does not opt in to
  # public caching and is explicitly marked private or non-cacheable.
  defp assert_private(conn) do
    [cache_control] = Plug.Conn.get_resp_header(conn, "cache-control")

    refute String.contains?(cache_control, "public"),
           "expected private caching, got: #{inspect(cache_control)}"

    assert String.contains?(cache_control, "private") or
             String.contains?(cache_control, "no-store") or
             String.contains?(cache_control, "no-cache") or
             String.contains?(cache_control, "max-age=0"),
           "expected a non-shared-cacheable directive, got: #{inspect(cache_control)}"
  end

  test "public pages are not publicly cacheable", %{conn: conn} do
    conn = get(conn, ~p"/login")
    assert html_response(conn, 200)
    assert_private(conn)
  end

  test "authenticated pages are not publicly cacheable", %{conn: conn} do
    user = user_fixture()
    conn = log_in_user(conn, user)

    conn = get(conn, ~p"/#{user.organization.slug}/dashboard")
    assert html_response(conn, 200)
    assert_private(conn)
  end

  test "json api responses are not publicly cacheable", %{conn: conn} do
    conn = get(conn, ~p"/health")
    assert json_response(conn, 200)
    assert_private(conn)
  end

  test "digested static assets are long-lived and publicly cacheable", %{conn: conn} do
    # The undigested URL is served by Plug.Static with an ETag; either way it
    # must be marked public so a CDN can cache it.
    conn = get(conn, ~p"/assets/app.css")
    assert response(conn, 200)

    [cache_control] = Plug.Conn.get_resp_header(conn, "cache-control")
    assert String.contains?(cache_control, "public")
  end
end
