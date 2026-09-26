defmodule AuthifyWeb.Plugs.NoStoreCacheTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures
  import Authify.OAuthFixtures
  import Plug.Conn

  alias AuthifyWeb.Plugs.NoStoreCache

  describe "NoStoreCache plug" do
    test "sets no-store and pragma headers", %{conn: conn} do
      conn = NoStoreCache.call(conn, [])

      assert get_resp_header(conn, "cache-control") == ["no-store"]
      assert get_resp_header(conn, "pragma") == ["no-cache"]
      refute conn.halted
    end
  end

  describe "sensitive endpoints" do
    test "OAuth token response is not stored (RFC 6749 Section 5.1)", %{conn: conn} do
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

      conn =
        post(conn, ~p"/#{organization.slug}/oauth/token", %{
          "grant_type" => "authorization_code",
          "client_id" => application.client_id,
          "client_secret" => application.client_secret,
          "code" => auth_code.code
        })

      assert json_response(conn, 200)["access_token"]
      assert get_resp_header(conn, "cache-control") == ["no-store"]
      assert get_resp_header(conn, "pragma") == ["no-cache"]
    end

    test "OAuth userinfo response is not stored", %{conn: conn} do
      organization = organization_fixture()

      conn = get(conn, ~p"/#{organization.slug}/oauth/userinfo")

      assert get_resp_header(conn, "cache-control") == ["no-store"]
      assert get_resp_header(conn, "pragma") == ["no-cache"]
    end

    test "management API response is not stored", %{conn: conn} do
      organization = organization_fixture()

      conn = get(conn, ~p"/#{organization.slug}/api/organization")

      assert get_resp_header(conn, "cache-control") == ["no-store"]
      assert get_resp_header(conn, "pragma") == ["no-cache"]
    end

    test "SCIM response is not stored", %{conn: conn} do
      organization = organization_fixture()

      conn = get(conn, ~p"/#{organization.slug}/scim/v2/ServiceProviderConfig")

      assert get_resp_header(conn, "cache-control") == ["no-store"]
      assert get_resp_header(conn, "pragma") == ["no-cache"]
    end

    test "password reset form is not stored", %{conn: conn} do
      conn = get(conn, ~p"/password_reset/new")

      assert get_resp_header(conn, "cache-control") == ["no-store"]
      assert get_resp_header(conn, "pragma") == ["no-cache"]
    end

    test "MFA verification response is not stored", %{conn: conn} do
      conn = get(conn, ~p"/mfa/verify")

      assert get_resp_header(conn, "cache-control") == ["no-store"]
      assert get_resp_header(conn, "pragma") == ["no-cache"]
    end
  end

  describe "non-sensitive endpoints" do
    test "login page keeps the default private cache header", %{conn: conn} do
      conn = get(conn, ~p"/login")

      assert html_response(conn, 200)
      assert get_resp_header(conn, "cache-control") == ["max-age=0, private, must-revalidate"]
    end
  end
end
