defmodule AuthifyWeb.Integration.WebAuthnTest do
  @moduledoc """
  Cross-protocol integration test demonstrating the IntegrationCase base template.

  Exercises a full WebAuthn registration and authentication lifecycle
  using WebAuthnAuthenticator, aliased automatically by IntegrationCase.
  """

  use AuthifyWeb.IntegrationCase

  @tag :capture_log
  test "registration and authentication lifecycle", %{org: org, admin: admin} do
    auth = WebAuthnAuthenticator.new()

    # ── Registration ──
    # fetch_registration_options builds its own conn internally; pass build_conn()
    assert {:ok, {reg_options, reg_conn}} =
             WebAuthnAuthenticator.fetch_registration_options(build_conn(), admin, org)

    assert is_binary(reg_options["challenge"])
    assert reg_options["rp"]["id"] == "localhost"

    assert {:ok, {credential, _auth}} =
             WebAuthnAuthenticator.create_credential(auth, reg_options)

    reg_complete_conn =
      post(reg_conn, "/#{org.slug}/profile/webauthn/register/complete", %{
        "attestationResponse" => credential,
        "credentialName" => "IntegrationCase Test Key"
      })

    assert json_response(reg_complete_conn, 200)["success"] == true

    # ── Authentication ──
    # The MFA flow requires mfa_pending_* session keys, set before calling
    # fetch_authentication_options.
    mfa_conn =
      build_conn()
      |> Plug.Test.init_test_session(%{
        mfa_pending_user_id: admin.id,
        mfa_pending_organization_id: org.id
      })

    assert {:ok, {auth_options, auth_begin_conn}} =
             WebAuthnAuthenticator.fetch_authentication_options(mfa_conn, org)

    assert is_binary(auth_options["challenge"])
    assert auth_options["rpId"] == "localhost"

    assert {:ok, {assertion, _auth}} =
             WebAuthnAuthenticator.sign_challenge(auth, auth_options)

    # Post the assertion to the SAME conn returned by fetch_authentication_options
    # (it carries the session with the pending challenge)
    auth_complete_conn =
      post(auth_begin_conn, "/mfa/webauthn/authenticate/complete", %{
        "assertionResponse" => assertion
      })

    assert json_response(auth_complete_conn, 200)["success"] == true
  end
end
