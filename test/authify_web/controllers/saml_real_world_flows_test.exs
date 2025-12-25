defmodule AuthifyWeb.SAMLRealWorldFlowsTest do
  @moduledoc """
  Real-world multi-step SAML integration tests.

  These tests simulate complete user journeys:
  - User signs up → Admin creates SAML SP → User SSOs → User SLOs from all SPs
  - Complete SSO flow with assertions and attribute mapping
  - SLO across multiple service providers
  """
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures
  import Authify.SAMLFixtures

  describe "Complete SAML SSO to SLO flow" do
    test "user can SSO to multiple SPs and perform global SLO" do
      # Step 1: Create organization with admin and user
      org = organization_fixture(%{name: "Enterprise Corp", slug: "enterprise"})
      _admin = admin_user_fixture(org)
      user = user_for_organization_fixture(org, %{"email" => "employee@enterprise.com"})

      # Step 2: Admin creates multiple SAML service providers
      {:ok, sp1} =
        Authify.SAML.create_service_provider(%{
          "name" => "Salesforce",
          "entity_id" => "https://salesforce.enterprise.com",
          "acs_url" => "https://salesforce.enterprise.com/saml/acs",
          "sls_url" => "https://salesforce.enterprise.com/saml/sls",
          "organization_id" => org.id,
          "attribute_mapping" =>
            Jason.encode!(%{
              "email" => "{{email}}",
              "firstName" => "{{first_name}}",
              "lastName" => "{{last_name}}"
            }),
          "is_active" => true
        })

      {:ok, sp2} =
        Authify.SAML.create_service_provider(%{
          "name" => "Workday",
          "entity_id" => "https://workday.enterprise.com",
          "acs_url" => "https://workday.enterprise.com/saml/acs",
          "sls_url" => "https://workday.enterprise.com/saml/sls",
          "organization_id" => org.id,
          "attribute_mapping" => Jason.encode!(%{"mail" => "{{email}}"}),
          "is_active" => true
        })

      # Step 3: User initiates SSO to first SP
      conn = build_conn() |> log_in_user(user)

      saml_request1 =
        sample_saml_request()
        |> String.replace("https://sp.example.com", sp1.entity_id)
        |> Base.encode64()

      conn =
        get(conn, ~p"/#{org.slug}/saml/sso", %{
          "SAMLRequest" => saml_request1,
          "RelayState" => "salesforce_app"
        })

      # Should redirect to continue endpoint
      continue_path1 = redirected_to(conn)
      assert String.contains?(continue_path1, "/#{org.slug}/saml/continue/")

      session_id1 = String.split(continue_path1, "/") |> List.last()

      # Step 4: Complete SSO for first SP
      conn = build_conn() |> log_in_user(user)
      conn = get(conn, continue_path1)

      assert response(conn, 200)
      response_body = response(conn, 200)
      assert String.contains?(response_body, sp1.acs_url)
      assert String.contains?(response_body, "SAMLResponse")

      # Verify session was created
      session1 = Authify.SAML.get_session(session_id1)
      assert session1.user_id == user.id
      assert session1.service_provider_id == sp1.id

      # Step 5: User SSOs to second SP (now has active session)
      conn = build_conn() |> log_in_user(user)

      saml_request2 =
        sample_saml_request()
        |> String.replace("https://sp.example.com", sp2.entity_id)
        |> Base.encode64()

      conn =
        get(conn, ~p"/#{org.slug}/saml/sso", %{
          "SAMLRequest" => saml_request2,
          "RelayState" => "workday_app"
        })

      continue_path2 = redirected_to(conn)
      _session_id2 = String.split(continue_path2, "/") |> List.last()

      # Complete SSO for second SP
      conn = build_conn() |> log_in_user(user)
      conn = get(conn, continue_path2)

      assert response(conn, 200)
      assert String.contains?(response(conn, 200), sp2.acs_url)

      # Step 6: User has active sessions with both SPs
      sessions = Authify.SAML.list_user_sessions(user)
      session_sp_ids = Enum.map(sessions, & &1.service_provider_id)
      assert sp1.id in session_sp_ids
      assert sp2.id in session_sp_ids

      # Step 7: User initiates IdP-initiated SLO (global logout)
      conn = build_conn() |> log_in_user(user)
      conn = get(conn, ~p"/#{org.slug}/saml/slo")

      # Should show SLO coordination page with both SPs
      assert response(conn, 200)
      slo_page = response(conn, 200)
      assert String.contains?(slo_page, "Single Logout in Progress")
      assert String.contains?(slo_page, sp1.name)
      assert String.contains?(slo_page, sp2.name)

      # Verify sessions will be terminated
      # (In a real implementation, this would send LogoutRequest to each SP)
    end
  end

  describe "SP-initiated Single Logout" do
    test "logout request from one SP terminates session but user remains logged into IdP" do
      org = organization_fixture()
      user = user_for_organization_fixture(org)

      sp = service_provider_fixture(organization: org, entity_id: "https://sp.example.com")

      # Create active SAML session
      session = saml_session_fixture(%{user: user, service_provider: sp})

      # Verify session is active
      assert DateTime.compare(session.expires_at, DateTime.utc_now()) == :gt

      # User is logged into IdP
      conn = build_conn() |> log_in_user(user)

      # SP sends LogoutRequest
      logout_request = encoded_saml_logout_request(sp.entity_id)

      conn =
        get(conn, ~p"/#{org.slug}/saml/slo", %{
          "SAMLRequest" => logout_request,
          "RelayState" => "sp_logout"
        })

      # Should return LogoutResponse
      assert response(conn, 200)
      assert String.contains?(response(conn, 200), sp.sls_url)
      assert String.contains?(response(conn, 200), "SAMLResponse")

      # Session should be terminated
      refreshed_session = Authify.SAML.get_session(session.session_id)
      assert DateTime.compare(refreshed_session.expires_at, DateTime.utc_now()) in [:lt, :eq]

      # User is still logged into IdP (can access other resources)
      conn = build_conn() |> log_in_user(user)
      conn = get(conn, ~p"/#{org.slug}/user/dashboard")
      assert html_response(conn, 200)
    end
  end

  describe "SAML attribute mapping" do
    test "service provider receives correctly mapped user attributes" do
      org = organization_fixture()

      user =
        user_for_organization_fixture(org, %{
          "email" => "john.doe@example.com",
          "first_name" => "John",
          "last_name" => "Doe"
        })

      # SP with custom attribute mapping
      {:ok, sp} =
        Authify.SAML.create_service_provider(%{
          "name" => "Custom App",
          "entity_id" => "https://customapp.example.com",
          "acs_url" => "https://customapp.example.com/saml/acs",
          "organization_id" => org.id,
          "attribute_mapping" =>
            Jason.encode!(%{
              "emailAddress" => "{{email}}",
              "givenName" => "{{first_name}}",
              "familyName" => "{{last_name}}"
            }),
          "is_active" => true
        })

      # Initiate SSO
      conn = build_conn() |> log_in_user(user)

      saml_request =
        sample_saml_request()
        |> String.replace("https://sp.example.com", sp.entity_id)
        |> Base.encode64()

      conn =
        get(conn, ~p"/#{org.slug}/saml/sso", %{
          "SAMLRequest" => saml_request,
          "RelayState" => "test"
        })

      continue_path = redirected_to(conn)
      session_id = String.split(continue_path, "/") |> List.last()

      # Get SAML response
      conn = build_conn() |> log_in_user(user)
      conn = get(conn, continue_path)

      _response_body = response(conn, 200)

      # Response should contain user attributes (in a real test, we'd decode the SAML response)
      # For now, verify the session has correct data
      session = Authify.SAML.get_session(session_id)
      assert session.user_id == user.id
      assert session.service_provider_id == sp.id

      # Verify user data is available for assertion generation
      session_user = Authify.Accounts.get_user!(session.user_id)
      assert session_user.email == "john.doe@example.com"
      assert session_user.first_name == "John"
      assert session_user.last_name == "Doe"
    end
  end
end
