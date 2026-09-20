defmodule AuthifyWeb.Auth.ReturnToTest do
  use AuthifyWeb.ConnCase, async: true

  alias AuthifyWeb.Auth.ReturnTo

  describe "safe_local_path/1" do
    test "accepts same-origin absolute paths" do
      assert {:ok, "/acme/groups/1/members"} = ReturnTo.safe_local_path("/acme/groups/1/members")

      assert {:ok, "/acme/oauth/authorize?client_id=abc&scope=openid"} =
               ReturnTo.safe_local_path("/acme/oauth/authorize?client_id=abc&scope=openid")

      assert {:ok, "/acme/saml/continue/sess-123"} =
               ReturnTo.safe_local_path("/acme/saml/continue/sess-123")

      assert {:ok, "/"} = ReturnTo.safe_local_path("/")
    end

    test "accepts paths whose query or fragment merely contains slashes" do
      assert {:ok, "/a?b=//evil.com"} = ReturnTo.safe_local_path("/a?b=//evil.com")

      assert {:ok, "/search?q=%2F%2Fevil.com"} =
               ReturnTo.safe_local_path("/search?q=%2F%2Fevil.com")
    end

    test "accepts percent-encoded characters that stay on-origin when decoded" do
      assert {:ok, "/foo%20bar"} = ReturnTo.safe_local_path("/foo%20bar")
      assert {:ok, "/caf%C3%A9"} = ReturnTo.safe_local_path("/caf%C3%A9")
    end

    test "rejects absolute URLs and host-bearing values" do
      assert :error = ReturnTo.safe_local_path("https://attacker.example/steal")
      assert :error = ReturnTo.safe_local_path("http://attacker.example")
      assert :error = ReturnTo.safe_local_path("javascript:alert(1)")
      assert :error = ReturnTo.safe_local_path("/\\evil.com")
    end

    test "rejects protocol-relative and backslash tricks" do
      assert :error = ReturnTo.safe_local_path("//evil.com")
      assert :error = ReturnTo.safe_local_path("//evil.com/path")
      assert :error = ReturnTo.safe_local_path("\\\\evil.com")
      assert :error = ReturnTo.safe_local_path("/\\/evil.com")
    end

    test "rejects encoded control characters and encoded slashes" do
      assert :error = ReturnTo.safe_local_path("/%09/evil.com")
      assert :error = ReturnTo.safe_local_path("/%0d%0a/evil.com")
      assert :error = ReturnTo.safe_local_path("/%2F%2Fevil.com")
      assert :error = ReturnTo.safe_local_path("/foo%5Cbar")
    end

    test "rejects raw control characters" do
      assert :error = ReturnTo.safe_local_path("/foo\tbar")
      assert :error = ReturnTo.safe_local_path("/foo\nbar")
      assert :error = ReturnTo.safe_local_path("/foo\rbar")
    end

    test "rejects blank and non-binary values" do
      assert :error = ReturnTo.safe_local_path("")
      assert :error = ReturnTo.safe_local_path(nil)
      assert :error = ReturnTo.safe_local_path(123)
      assert :error = ReturnTo.safe_local_path(["//evil.com"])
    end

    test "rejects relative paths that are not rooted" do
      assert :error = ReturnTo.safe_local_path("acme/groups")
      assert :error = ReturnTo.safe_local_path("../evil")
    end

    test "does not raise on invalid UTF-8" do
      for value <- ["/\xFF", "/\x80\x80", "/foo\xFFbar", "/\xC0\xAF", "/\xED\xA0\x80"] do
        assert :error = ReturnTo.safe_local_path(value)
      end
    end

    test "rejects values longer than the session-safe bound" do
      assert {:ok, _} = ReturnTo.safe_local_path("/" <> String.duplicate("a", 1023))
      assert :error = ReturnTo.safe_local_path("/" <> String.duplicate("a", 1024))
    end

    test "rejects decoded control characters other than tab/newline/CR" do
      for value <- ["/%00/evil.com", "/%08/evil.com", "/%0B/evil.com", "/%1F/evil.com"] do
        assert :error = ReturnTo.safe_local_path(value)
      end

      assert :error = ReturnTo.safe_local_path("/%7F/evil.com")
    end

    test "accepts encoded dot-segments that only normalize within the origin" do
      # These resolve to the same origin (path-only) and are not open redirects;
      # they must not be treated as unsafe.
      assert {:ok, _} = ReturnTo.safe_local_path("/%2e%2e/evil.com")
      assert {:ok, _} = ReturnTo.safe_local_path("/..//evil.com")
    end

    test "accepts scheme-lookalike paths that remain same-origin pathnames" do
      # A leading slash forces path interpretation: these are pathnames on the
      # current origin, not URLs with schemes.
      assert {:ok, _} = ReturnTo.safe_local_path("/javascript:alert(1)")
      assert {:ok, _} = ReturnTo.safe_local_path("/data:text/html;base64,x")

      assert {:ok, _} =
               ReturnTo.safe_local_path("/%6a%61%76%61%73%63%72%69%70%74:alert(1)")
    end
  end

  describe "store/2, peek/1, consume/1, destination/2" do
    test "stores only safe values and clears unsafe ones" do
      conn = Plug.Test.init_test_session(build_conn(), %{})

      conn = ReturnTo.store(conn, "/safe/path")
      assert ReturnTo.peek(conn) == "/safe/path"

      conn = ReturnTo.store(conn, "https://evil.example")
      assert ReturnTo.peek(conn) == nil
    end

    test "consume returns the value once and clears it" do
      conn = Plug.Test.init_test_session(build_conn(), %{})
      conn = ReturnTo.store(conn, "/safe/path")

      {conn, path} = ReturnTo.consume(conn)
      assert path == "/safe/path"
      assert ReturnTo.peek(conn) == nil
    end

    test "destination falls back to the default when nothing is stored" do
      conn = Plug.Test.init_test_session(build_conn(), %{})

      assert {_conn, "/default"} = ReturnTo.destination(conn, "/default")
    end

    test "destination prefers a stored value over the default" do
      conn = Plug.Test.init_test_session(build_conn(), %{})
      conn = ReturnTo.store(conn, "/stored")

      assert {conn, "/stored"} = ReturnTo.destination(conn, "/default")
      assert ReturnTo.peek(conn) == nil
    end

    test "re-validates on read: an unsafe session value is treated as absent" do
      # Simulates a session value that bypassed store/2 (e.g. a future writer
      # or a stale value). Consumption must refuse it, including via the
      # WebAuthn JSON redirect_url path that bypasses Phoenix's redirect guard.
      conn = Plug.Test.init_test_session(build_conn(), %{return_to: "https://evil.example/steal"})

      assert ReturnTo.peek(conn) == nil
      assert {_conn, nil} = ReturnTo.consume(conn)

      conn = Plug.Test.init_test_session(build_conn(), %{return_to: "//evil.com"})
      assert {_conn, "/default"} = ReturnTo.destination(conn, "/default")
    end
  end
end
