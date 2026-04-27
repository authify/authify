defmodule AuthifyWeb.SAMLIntegrationTest do
  @moduledoc """
  Integration test demonstrating the IntegrationCase base template.

  Exercises a complete SAML SP-initiated SSO flow using SAMLServiceProvider,
  which is aliased automatically by IntegrationCase.
  """

  use AuthifyWeb.IntegrationCase

  import Authify.SAMLFixtures

  test "SP-initiated SSO flow: signed AuthnRequest → signed assertion", %{
    org: org,
    admin: admin
  } do
    # Authify must have a signing certificate before it will sign assertions
    certificate_fixture(%{organization: org})

    # SAMLServiceProvider.new/1 generates an RSA key pair, self-signed cert,
    # and registers the SP in the database for this org.
    sp = SAMLServiceProvider.new(org)

    # Step 1: Build and submit a signed AuthnRequest
    {:ok, {encoded_request, request_id}} = SAMLServiceProvider.build_authn_request(sp)

    sso_resp =
      build_conn()
      |> log_in_user(admin)
      |> get("/#{org.slug}/saml/sso", %{
        "SAMLRequest" => encoded_request,
        "RelayState" => "integration-test"
      })

    assert sso_resp.status == 302
    continue_path = redirected_to(sso_resp)
    assert String.contains?(continue_path, "/#{org.slug}/saml/continue/")

    # Step 2: Follow the continue redirect as the authenticated user
    assertion_resp =
      build_conn()
      |> log_in_user(admin)
      |> get(continue_path)

    assert assertion_resp.status == 200
    assert String.contains?(assertion_resp.resp_body, "SAMLResponse")

    # Step 3: SP extracts and validates the signed assertion
    assert {:ok, response_xml} = SAMLServiceProvider.extract_response(assertion_resp)

    assert {:ok, assertion} =
             SAMLServiceProvider.validate_response(sp, response_xml, org,
               in_response_to: request_id
             )

    assert assertion.in_response_to == request_id
    assert is_map(assertion.attributes)
  end
end
