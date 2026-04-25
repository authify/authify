defmodule AuthifyTest.WebAuthnIntegrationTest do
  @moduledoc false

  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  alias AuthifyTest.WebAuthnAuthenticator

  describe "full WebAuthn registration and authentication lifecycle" do
    setup do
      org = organization_fixture()
      user = user_for_organization_fixture(org)
      auth = WebAuthnAuthenticator.new()
      %{org: org, user: user, auth: auth}
    end

    test "registers a credential and authenticates with it", %{
      org: org,
      user: user,
      auth: auth
    } do
      # ── Registration ──
      {:ok, {reg_options, reg_conn}} =
        WebAuthnAuthenticator.fetch_registration_options(build_conn(), user, org)

      assert reg_options["challenge"]
      assert reg_options["rp"]["id"] == "localhost"

      {:ok, {credential_params, _auth}} =
        WebAuthnAuthenticator.create_credential(auth, reg_options)

      reg_complete_conn =
        post(reg_conn, "/#{org.slug}/profile/webauthn/register/complete", %{
          "attestationResponse" => credential_params,
          "credentialName" => "Test Key"
        })

      assert json_response(reg_complete_conn, 200)["success"] == true

      # ── Authentication ──
      mfa_conn =
        build_conn()
        |> Plug.Test.init_test_session(%{
          mfa_pending_user_id: user.id,
          mfa_pending_organization_id: org.id
        })

      {:ok, {auth_options, auth_begin_conn}} =
        WebAuthnAuthenticator.fetch_authentication_options(mfa_conn, org)

      assert auth_options["challenge"]
      assert auth_options["rpId"] == "localhost"

      {:ok, {assertion_params, _auth}} =
        WebAuthnAuthenticator.sign_challenge(auth, auth_options)

      auth_complete_conn =
        post(auth_begin_conn, "/mfa/webauthn/authenticate/complete", %{
          "assertionResponse" => assertion_params
        })

      assert json_response(auth_complete_conn, 200)["success"] == true
    end

    test "second authentication with incremented counter also succeeds", %{
      org: org,
      user: user,
      auth: auth
    } do
      # Register
      {:ok, {reg_options, reg_conn}} =
        WebAuthnAuthenticator.fetch_registration_options(build_conn(), user, org)

      {:ok, {credential_params, _}} = WebAuthnAuthenticator.create_credential(auth, reg_options)

      post(reg_conn, "/#{org.slug}/profile/webauthn/register/complete", %{
        "attestationResponse" => credential_params,
        "credentialName" => "My Key"
      })

      # First authentication — counter goes from 0 to 1
      mfa_conn1 =
        build_conn()
        |> Plug.Test.init_test_session(%{
          mfa_pending_user_id: user.id,
          mfa_pending_organization_id: org.id
        })

      {:ok, {auth_options1, auth_conn1}} =
        WebAuthnAuthenticator.fetch_authentication_options(mfa_conn1, org)

      {:ok, {assertion1, auth_after_first}} =
        WebAuthnAuthenticator.sign_challenge(auth, auth_options1)

      assert json_response(
               post(auth_conn1, "/mfa/webauthn/authenticate/complete", %{
                 "assertionResponse" => assertion1
               }),
               200
             )["success"] == true

      # Second authentication — use updated authenticator (counter = 1 → 2)
      mfa_conn2 =
        build_conn()
        |> Plug.Test.init_test_session(%{
          mfa_pending_user_id: user.id,
          mfa_pending_organization_id: org.id
        })

      {:ok, {auth_options2, auth_conn2}} =
        WebAuthnAuthenticator.fetch_authentication_options(mfa_conn2, org)

      {:ok, {assertion2, _}} =
        WebAuthnAuthenticator.sign_challenge(auth_after_first, auth_options2)

      assert json_response(
               post(auth_conn2, "/mfa/webauthn/authenticate/complete", %{
                 "assertionResponse" => assertion2
               }),
               200
             )["success"] == true
    end

    test "server rejects authentication with replayed (non-incremented) counter", %{
      org: org,
      user: user,
      auth: auth
    } do
      # Register
      {:ok, {reg_options, reg_conn}} =
        WebAuthnAuthenticator.fetch_registration_options(build_conn(), user, org)

      {:ok, {credential_params, _}} = WebAuthnAuthenticator.create_credential(auth, reg_options)

      post(reg_conn, "/#{org.slug}/profile/webauthn/register/complete", %{
        "attestationResponse" => credential_params,
        "credentialName" => "My Key"
      })

      # First authentication — succeeds and advances DB counter to 1
      mfa_conn1 =
        build_conn()
        |> Plug.Test.init_test_session(%{
          mfa_pending_user_id: user.id,
          mfa_pending_organization_id: org.id
        })

      {:ok, {auth_options1, auth_conn1}} =
        WebAuthnAuthenticator.fetch_authentication_options(mfa_conn1, org)

      # Save the assertion BEFORE the first auth completes (counter = 1 in assertion)
      {:ok, {assertion_counter_1, _}} = WebAuthnAuthenticator.sign_challenge(auth, auth_options1)

      post(auth_conn1, "/mfa/webauthn/authenticate/complete", %{
        "assertionResponse" => assertion_counter_1
      })

      # Replay: second authentication using the SAME assertion (counter = 1 again)
      # The DB now has sign_count = 1, so new_sign_count = 1 is NOT > 1 → rejected
      mfa_conn2 =
        build_conn()
        |> Plug.Test.init_test_session(%{
          mfa_pending_user_id: user.id,
          mfa_pending_organization_id: org.id
        })

      {:ok, {_auth_options2, auth_conn2}} =
        WebAuthnAuthenticator.fetch_authentication_options(mfa_conn2, org)

      # Sign with stale authenticator — produces assertion with counter = 1
      {:ok, {replayed_assertion, _}} = WebAuthnAuthenticator.sign_challenge(auth, auth_options1)

      replay_response =
        json_response(
          post(auth_conn2, "/mfa/webauthn/authenticate/complete", %{
            "assertionResponse" => replayed_assertion
          }),
          200
        )

      assert replay_response["success"] == false
    end
  end
end
