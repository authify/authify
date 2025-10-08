defmodule AuthifyWeb.SAMLControllerTest do
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures
  import Authify.SAMLFixtures

  describe "metadata" do
    test "GET /saml/metadata returns valid SAML metadata XML", %{conn: conn} do
      organization = organization_fixture()
      conn = get(conn, ~p"/#{organization.slug}/saml/metadata")

      assert response(conn, 200)

      assert get_resp_header(conn, "content-type") == [
               "application/samlmetadata+xml; charset=utf-8"
             ]

      response_body = response(conn, 200)
      assert String.contains?(response_body, "EntityDescriptor")
      assert String.contains?(response_body, "IDPSSODescriptor")
      assert String.contains?(response_body, "SingleSignOnService")
      assert String.contains?(response_body, "SingleLogoutService")
      assert String.contains?(response_body, "/saml/sso")
      assert String.contains?(response_body, "/saml/slo")
    end
  end

  describe "sso" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      sp = service_provider_fixture(organization: organization)

      %{organization: organization, user: user, service_provider: sp}
    end

    test "GET /saml/sso without SAMLRequest returns error", %{
      conn: conn,
      organization: organization
    } do
      conn = get(conn, ~p"/#{organization.slug}/saml/sso")

      assert response(conn, 400)
      assert response(conn, 400) =~ "Missing SAML request"
    end

    test "GET /saml/sso with invalid SAMLRequest returns error", %{
      conn: conn,
      organization: organization
    } do
      conn = get(conn, ~p"/#{organization.slug}/saml/sso", %{"SAMLRequest" => "invalid_request"})

      assert response(conn, 400)
      assert response(conn, 400) =~ "Invalid SAML request"
    end

    test "GET /saml/sso with valid SAMLRequest redirects unauthenticated user to login", %{
      conn: conn,
      service_provider: _sp,
      organization: organization
    } do
      saml_request = encoded_saml_request()

      conn =
        get(conn, ~p"/#{organization.slug}/saml/sso", %{
          "SAMLRequest" => saml_request,
          "RelayState" => "test_relay"
        })

      assert redirected_to(conn) =~ "/login"
      assert redirected_to(conn) =~ "saml_session="
      assert redirected_to(conn) =~ "return_to="
    end

    test "GET /saml/sso with authenticated user shows consent (auto-redirects)", %{
      conn: conn,
      user: user,
      service_provider: _sp,
      organization: organization
    } do
      conn = log_in_user(conn, user)
      saml_request = encoded_saml_request()

      conn =
        get(conn, ~p"/#{organization.slug}/saml/sso", %{
          "SAMLRequest" => saml_request,
          "RelayState" => "test_relay"
        })

      # Should redirect to continue endpoint (auto-consent)
      assert redirected_to(conn) =~ "/saml/continue/"
    end

    test "POST /saml/sso works with HTTP-POST binding", %{
      conn: conn,
      user: user,
      service_provider: _sp,
      organization: organization
    } do
      conn = log_in_user(conn, user)
      saml_request = encoded_saml_request()

      conn =
        post(conn, ~p"/#{organization.slug}/saml/sso", %{
          "SAMLRequest" => saml_request,
          "RelayState" => "test_relay"
        })

      # Should redirect to continue endpoint
      assert redirected_to(conn) =~ "/saml/continue/"
    end
  end

  describe "continue" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      sp = service_provider_fixture(organization: organization)
      session = saml_session_fixture(%{user: user, service_provider: sp})

      %{organization: organization, user: user, service_provider: sp, session: session}
    end

    test "GET /saml/continue/:session_id without authentication redirects to login", %{
      conn: conn,
      session: session,
      organization: organization
    } do
      conn = get(conn, ~p"/#{organization.slug}/saml/continue/#{session.session_id}")

      assert redirected_to(conn) =~ "/login"
    end

    test "GET /saml/continue/:session_id with authentication returns SAML response form", %{
      conn: conn,
      user: user,
      session: session,
      service_provider: sp,
      organization: organization
    } do
      conn = log_in_user(conn, user)
      conn = get(conn, ~p"/#{organization.slug}/saml/continue/#{session.session_id}")

      assert response(conn, 200)
      assert get_resp_header(conn, "content-type") == ["text/html; charset=utf-8"]

      response_body = response(conn, 200)
      assert String.contains?(response_body, "SAML Response")
      assert String.contains?(response_body, sp.acs_url)
      assert String.contains?(response_body, "SAMLResponse")
      assert String.contains?(response_body, "onload=\"document.forms[0].submit()\"")
    end

    test "GET /saml/continue/:session_id with invalid session returns error", %{
      conn: conn,
      user: user,
      organization: organization
    } do
      conn = log_in_user(conn, user)
      conn = get(conn, ~p"/#{organization.slug}/saml/continue/invalid_session_id")

      assert response(conn, 400)
      assert response(conn, 400) =~ "Invalid or expired SAML session"
    end
  end

  describe "slo - Single Logout" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      sp = service_provider_fixture(organization: organization)
      session = saml_session_fixture(%{user: user, service_provider: sp})

      %{organization: organization, user: user, service_provider: sp, session: session}
    end

    test "GET /saml/slo without parameters redirects unauthenticated user to login", %{
      conn: conn,
      organization: organization
    } do
      conn = get(conn, ~p"/#{organization.slug}/saml/slo")

      assert redirected_to(conn) == "/login"
    end

    test "GET /saml/slo without parameters and no SAML sessions redirects to logout" do
      # Create fresh user without any SAML sessions
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      conn = build_conn() |> log_in_user(user) |> get(~p"/#{organization.slug}/saml/slo")

      assert redirected_to(conn) == "/logout"
    end

    test "GET /saml/slo without parameters shows logout coordination page", %{
      conn: conn,
      user: user,
      session: _session,
      organization: organization
    } do
      conn = log_in_user(conn, user)
      conn = get(conn, ~p"/#{organization.slug}/saml/slo")

      assert response(conn, 200)
      response_body = response(conn, 200)
      assert String.contains?(response_body, "Single Logout in Progress")
      assert String.contains?(response_body, "Test Service Provider")
    end

    test "GET /saml/slo with SAMLRequest handles SP-initiated logout", %{
      conn: conn,
      user: user,
      service_provider: sp,
      organization: organization
    } do
      conn = log_in_user(conn, user)
      logout_request = encoded_saml_logout_request()

      conn =
        get(conn, ~p"/#{organization.slug}/saml/slo", %{
          "SAMLRequest" => logout_request,
          "RelayState" => "test_relay"
        })

      assert response(conn, 200)
      response_body = response(conn, 200)
      assert String.contains?(response_body, "SAML Logout Response")
      assert String.contains?(response_body, "SAMLResponse")
      assert String.contains?(response_body, sp.sls_url || sp.acs_url)
    end

    test "GET /saml/slo with SAMLRequest for unknown SP returns error", %{
      conn: conn,
      organization: organization
    } do
      logout_request = sample_saml_logout_request()
      # Modify to use unknown issuer
      unknown_issuer_request =
        String.replace(logout_request, "https://sp.example.com", "https://unknown-sp.example.com")

      encoded_request = Base.encode64(unknown_issuer_request)

      conn = get(conn, ~p"/#{organization.slug}/saml/slo", %{"SAMLRequest" => encoded_request})

      assert response(conn, 400)
      assert response(conn, 400) =~ "Unknown service provider"
    end

    test "GET /saml/slo with invalid SAMLRequest returns error", %{
      conn: conn,
      organization: organization
    } do
      conn = get(conn, ~p"/#{organization.slug}/saml/slo", %{"SAMLRequest" => "invalid_request"})

      assert response(conn, 400)
      assert response(conn, 400) =~ "Invalid logout request"
    end

    test "GET /saml/slo with SAMLResponse redirects to logout completion", %{
      conn: conn,
      organization: organization
    } do
      conn = get(conn, ~p"/#{organization.slug}/saml/slo", %{"SAMLResponse" => "dummy_response"})

      assert redirected_to(conn) == "/logout?slo_complete=true"
    end

    test "POST /saml/slo works with HTTP-POST binding", %{
      conn: conn,
      user: user,
      service_provider: _sp,
      organization: organization
    } do
      conn = log_in_user(conn, user)
      logout_request = encoded_saml_logout_request()

      conn =
        post(conn, ~p"/#{organization.slug}/saml/slo", %{
          "SAMLRequest" => logout_request,
          "RelayState" => "test_relay"
        })

      assert response(conn, 200)
      assert String.contains?(response(conn, 200), "SAML Logout Response")
    end
  end

  describe "SAML error handling" do
    setup do
      organization = organization_fixture()
      %{organization: organization}
    end

    test "handles malformed XML gracefully", %{conn: conn, organization: organization} do
      malformed_request = "not_base64_encoded_xml"

      conn = get(conn, ~p"/#{organization.slug}/saml/sso", %{"SAMLRequest" => malformed_request})

      assert response(conn, 400)
      assert response(conn, 400) =~ "Invalid SAML request"
    end

    test "handles missing service provider gracefully", %{conn: conn, organization: organization} do
      # Create a valid SAML request but for a non-existent service provider
      saml_request = sample_saml_request()

      unknown_sp_request =
        String.replace(saml_request, "https://sp.example.com", "https://nonexistent.example.com")

      encoded_request = Base.encode64(unknown_sp_request)

      conn = get(conn, ~p"/#{organization.slug}/saml/sso", %{"SAMLRequest" => encoded_request})

      assert response(conn, 400)
      assert response(conn, 400) =~ "Unknown service provider"
    end
  end

  describe "SAML security" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      sp = service_provider_fixture(organization: organization)

      %{organization: organization, user: user, service_provider: sp}
    end

    test "SAML requests are validated against registered service providers", %{
      conn: conn,
      user: user,
      service_provider: _sp,
      organization: organization
    } do
      conn = log_in_user(conn, user)

      # Valid SP should work
      saml_request = encoded_saml_request()
      conn = get(conn, ~p"/#{organization.slug}/saml/sso", %{"SAMLRequest" => saml_request})
      assert redirected_to(conn) =~ "/saml/continue/"

      # Invalid SP should fail
      unknown_sp_request =
        sample_saml_request()
        |> String.replace("https://sp.example.com", "https://evil-sp.example.com")
        |> Base.encode64()

      conn =
        build_conn()
        |> log_in_user(user)
        |> get(~p"/#{organization.slug}/saml/sso", %{"SAMLRequest" => unknown_sp_request})

      assert response(conn, 400)
    end

    test "inactive service providers are rejected", %{
      conn: conn,
      user: user,
      service_provider: sp,
      organization: organization
    } do
      # Deactivate the service provider
      {:ok, _} = Authify.SAML.update_service_provider(sp, %{is_active: false})

      conn = log_in_user(conn, user)
      saml_request = encoded_saml_request()

      conn = get(conn, ~p"/#{organization.slug}/saml/sso", %{"SAMLRequest" => saml_request})

      assert response(conn, 400)
      assert response(conn, 400) =~ "Unknown service provider"
    end

    test "sessions are properly scoped to users", %{
      user: user,
      service_provider: sp,
      organization: organization
    } do
      # Create sessions for different users
      other_organization = organization_fixture()
      other_user = user_for_organization_fixture(other_organization)

      session1 = saml_session_fixture(%{user: user, service_provider: sp})
      session2 = saml_session_fixture(%{user: other_user, service_provider: sp})

      # User should only see their own session
      conn = build_conn() |> log_in_user(user)
      conn = get(conn, ~p"/#{organization.slug}/saml/continue/#{session1.session_id}")
      assert response(conn, 200)

      # User should not access other user's session
      conn = build_conn() |> log_in_user(user)
      conn = get(conn, ~p"/#{organization.slug}/saml/continue/#{session2.session_id}")
      assert response(conn, 400)
    end
  end

  describe "SAML integration flows" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      sp = service_provider_fixture(organization: organization)

      %{organization: organization, user: user, service_provider: sp}
    end

    test "complete SSO flow from request to response", %{
      conn: conn,
      user: user,
      service_provider: sp,
      organization: organization
    } do
      # Step 1: SP sends SAML request
      saml_request = encoded_saml_request()

      conn =
        get(conn, ~p"/#{organization.slug}/saml/sso", %{
          "SAMLRequest" => saml_request,
          "RelayState" => "test_state"
        })

      # Step 2: User is redirected to login
      login_url = redirected_to(conn)
      assert String.contains?(login_url, "/login")
      assert String.contains?(login_url, "saml_session=")

      # Extract session ID from redirect URL (includes org slug)
      # The return_to is URL-encoded: /test-org/saml/continue/SESSION_ID
      # becomes: %2Ftest-org%2Fsaml%2Fcontinue%2FSESSION_ID
      session_id =
        case Regex.run(~r/return_to=([^&]+)/, login_url) do
          [_, encoded_path] ->
            URI.decode(encoded_path)
            |> String.split("/")
            |> List.last()

          _ ->
            flunk("Could not extract session ID from login_url: #{login_url}")
        end

      # Step 3: User logs in and continues SAML flow
      conn = build_conn() |> log_in_user(user)
      conn = get(conn, "/#{organization.slug}/saml/continue/#{session_id}")

      # Step 4: User gets SAML response form
      assert response(conn, 200)
      response_body = response(conn, 200)
      assert String.contains?(response_body, sp.acs_url)
      assert String.contains?(response_body, "SAMLResponse")
      assert String.contains?(response_body, "RelayState")
      assert String.contains?(response_body, "test_state")
    end

    test "complete SLO flow from logout request to response", %{
      conn: conn,
      user: user,
      service_provider: sp,
      organization: organization
    } do
      # Create an active SAML session
      session = saml_session_fixture(%{user: user, service_provider: sp})

      # SP initiates logout
      conn = log_in_user(conn, user)
      logout_request = encoded_saml_logout_request()

      conn =
        get(conn, ~p"/#{organization.slug}/saml/slo", %{
          "SAMLRequest" => logout_request,
          "RelayState" => "logout_state"
        })

      # Should get logout response form
      assert response(conn, 200)
      response_body = response(conn, 200)
      assert String.contains?(response_body, "SAML Logout Response")
      assert String.contains?(response_body, "SAMLResponse")
      assert String.contains?(response_body, "logout_state")
      assert String.contains?(response_body, sp.sls_url || sp.acs_url)

      # Verify session was terminated
      refreshed_session = Authify.SAML.get_session(session.session_id)
      assert DateTime.compare(refreshed_session.expires_at, DateTime.utc_now()) in [:lt, :eq]
    end
  end
end
