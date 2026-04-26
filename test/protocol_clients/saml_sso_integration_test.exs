defmodule AuthifyTest.SAMLSSOIntegrationTest do
  @moduledoc false

  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures
  import Authify.SAMLFixtures

  alias AuthifyTest.SAMLServiceProvider

  describe "SP-initiated SSO with signed AuthnRequest and signed assertion" do
    setup do
      org = organization_fixture()
      user = user_for_organization_fixture(org, %{"email" => "sso.user@example.com"})

      # Create an IdP signing cert so Authify will sign the assertion in responses
      certificate_fixture(%{organization: org})

      sp = SAMLServiceProvider.new(org)

      %{org: org, user: user, sp: sp}
    end

    test "complete SP-initiated SSO flow: signed request → signed assertion → validated", %{
      org: org,
      user: user,
      sp: sp
    } do
      # ── Step 1: SP generates a signed AuthnRequest ─────────────────────
      {:ok, {encoded_request, request_id}} = SAMLServiceProvider.build_authn_request(sp)

      # Verify the request is actually signed
      assert String.contains?(Base.decode64!(encoded_request), "<ds:Signature")

      # ── Step 2: Post signed AuthnRequest to Authify's SSO endpoint ─────
      conn = build_conn() |> log_in_user(user)

      sso_resp =
        get(conn, "/#{org.slug}/saml/sso", %{
          "SAMLRequest" => encoded_request,
          "RelayState" => "integration-test"
        })

      assert sso_resp.status == 302
      continue_path = redirected_to(sso_resp)
      assert String.contains?(continue_path, "/#{org.slug}/saml/continue/")

      session_id = String.split(continue_path, "/") |> List.last()

      # ── Step 3: Follow the continue redirect as the authenticated user ─
      continue_conn = build_conn() |> log_in_user(user)
      assertion_resp = get(continue_conn, continue_path)

      assert assertion_resp.status == 200
      body = assertion_resp.resp_body
      assert String.contains?(body, sp.acs_url)
      assert String.contains?(body, "SAMLResponse")

      # ── Step 4: SP extracts the SAMLResponse from the auto-submit form ─
      {:ok, response_xml} = SAMLServiceProvider.extract_response(assertion_resp)

      assert String.contains?(response_xml, "Response") or
               String.contains?(response_xml, "response")

      # ── Step 5: SP validates the response ────────────────────────────────
      assert {:ok, assertion} =
               SAMLServiceProvider.validate_response(sp, response_xml, org,
                 in_response_to: request_id
               )

      # ── Step 6: Verify assertion contents ────────────────────────────────
      assert assertion.in_response_to == request_id
      assert assertion.session_index == session_id
      assert is_map(assertion.attributes)

      # ── Step 7: Verify SAML session was persisted correctly ──────────────
      saml_session = Authify.SAML.get_session(session_id)
      assert saml_session.user_id == user.id
      assert saml_session.service_provider_id == sp.sp_record.id
    end

    test "Authify rejects a signed AuthnRequest from an unregistered SP", %{
      org: org,
      user: user,
      sp: sp
    } do
      {:ok, {encoded_request, _}} = SAMLServiceProvider.build_authn_request(sp)
      xml = Base.decode64!(encoded_request)

      # Replace SP's entity_id with one that is not registered
      tampered_xml = String.replace(xml, sp.entity_id, "https://unknown-sp.example.com")
      tampered_encoded = Base.encode64(tampered_xml)

      conn = build_conn() |> log_in_user(user)
      resp = get(conn, "/#{org.slug}/saml/sso", %{"SAMLRequest" => tampered_encoded})

      assert resp.status == 400
      assert String.contains?(resp.resp_body, "Unknown service provider")
    end
  end

  describe "SP-initiated SLO flow" do
    setup do
      org = organization_fixture()
      user = user_for_organization_fixture(org)
      certificate_fixture(%{organization: org})
      sp = SAMLServiceProvider.new(org)
      %{org: org, user: user, sp: sp}
    end

    test "SP-initiated LogoutRequest is processed and SP validates the LogoutResponse", %{
      org: org,
      user: user,
      sp: sp
    } do
      # Establish a SAML session via SSO first
      {:ok, {encoded_request, _}} = SAMLServiceProvider.build_authn_request(sp)

      sso_conn = build_conn() |> log_in_user(user)

      sso_resp =
        get(sso_conn, "/#{org.slug}/saml/sso", %{"SAMLRequest" => encoded_request})

      continue_path = redirected_to(sso_resp)
      session_id = String.split(continue_path, "/") |> List.last()

      continue_conn = build_conn() |> log_in_user(user)
      get(continue_conn, continue_path)

      # SP initiates logout using the session_id as session_index
      {:ok, {encoded_logout_req, _}} = SAMLServiceProvider.build_logout_request(sp, session_id)

      logout_conn = build_conn() |> log_in_user(user)

      slo_resp =
        get(logout_conn, "/#{org.slug}/saml/slo", %{
          "SAMLRequest" => encoded_logout_req,
          "RelayState" => "logout-relay"
        })

      # Authify should return a LogoutResponse form pointing to the SP's sls_url
      assert slo_resp.status == 200
      assert String.contains?(slo_resp.resp_body, "SAMLResponse")
      assert String.contains?(slo_resp.resp_body, sp.sls_url)

      # SP validates the logout response
      assert {:ok, :logged_out} = SAMLServiceProvider.validate_logout_response(sp, slo_resp)
    end
  end
end
