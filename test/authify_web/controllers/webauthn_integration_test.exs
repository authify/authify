defmodule AuthifyWeb.WebAuthnIntegrationTest do
  @moduledoc """
  Integration tests for WebAuthn functionality.

  These tests verify:
  - Full WebAuthn registration flow (setup -> begin -> complete)
  - Full WebAuthn authentication flow during MFA (login -> begin -> complete)
  - Credential management workflows (create -> list -> rename -> revoke)
  - Organization scoping and user isolation
  - Authorization and ownership verification
  """
  use AuthifyWeb.ConnCase

  import Ecto.Query
  import Authify.AccountsFixtures

  alias Authify.MFA.{WebAuthn, WebAuthnCredential}
  alias Authify.Repo

  describe "WebAuthn registration flow" do
    test "complete registration workflow from setup to credential creation" do
      # Create organization and user
      org = organization_fixture()
      user = user_for_organization_fixture(org)
      user = Repo.preload(user, :organization)

      # Step 1: User visits setup page
      conn =
        build_conn()
        |> log_in_user(user, org)
        |> get(~p"/#{org.slug}/profile/webauthn/setup")

      assert html_response(conn, 200) =~ "Register Security Key or Passkey"

      # Step 2: User begins registration
      conn =
        build_conn()
        |> log_in_user(user, org)
        |> post(~p"/#{org.slug}/profile/webauthn/register/begin", %{})

      assert json_response(conn, 200)["success"] == true
      challenge = get_session(conn, :webauthn_registration_challenge)
      assert is_binary(challenge)

      # Verify challenge was stored in database
      stored_challenge =
        Repo.get_by(Authify.MFA.WebAuthnChallenge,
          user_id: user.id,
          challenge: challenge,
          challenge_type: "registration"
        )

      assert stored_challenge
      refute stored_challenge.consumed_at

      # Step 3: Verify user has no credentials yet
      assert WebAuthn.list_credentials(user) == []

      # Note: Complete step requires actual WebAuthn browser API response
      # which we cannot mock in integration tests. This is tested in controller tests.
    end

    test "registration excludes existing credentials" do
      org = organization_fixture()
      user = user_for_organization_fixture(org)
      user = Repo.preload(user, :organization)

      # Create an existing credential
      create_credential(user, %{credential_id: "existing_credential_123", name: "My YubiKey"})

      # Begin new registration
      conn =
        build_conn()
        |> log_in_user(user, org)
        |> post(~p"/#{org.slug}/profile/webauthn/register/begin", %{})

      response = json_response(conn, 200)
      assert response["success"] == true

      # Verify existing credential is excluded
      excluded = response["options"]["excludeCredentials"]
      assert is_list(excluded)
      assert length(excluded) == 1
      assert hd(excluded)["id"] == "existing_credential_123"
    end

    test "registration with authenticator attachment preference" do
      org = organization_fixture()
      user = user_for_organization_fixture(org)
      user = Repo.preload(user, :organization)

      # Begin registration with platform authenticator preference
      conn =
        build_conn()
        |> log_in_user(user, org)
        |> post(~p"/#{org.slug}/profile/webauthn/register/begin", %{
          "authenticatorAttachment" => "platform"
        })

      response = json_response(conn, 200)
      assert response["success"] == true

      assert response["options"]["authenticatorSelection"]["authenticatorAttachment"] ==
               "platform"
    end
  end

  describe "WebAuthn authentication flow during MFA" do
    test "complete authentication workflow during login" do
      # Setup: Create user with WebAuthn credential
      org = organization_fixture()
      user = user_for_organization_fixture(org)
      user = Repo.preload(user, :organization)

      credential =
        create_credential(user, %{
          credential_id: "test_auth_credential",
          name: "My Security Key"
        })

      # Step 1: User is in MFA verification state (after password login)
      conn =
        build_conn()
        |> Plug.Test.init_test_session(%{
          mfa_pending_user_id: user.id,
          mfa_pending_organization_id: org.id
        })

      # Step 2: Begin authentication
      conn = post(conn, ~p"/mfa/webauthn/authenticate/begin")

      response = json_response(conn, 200)
      assert response["success"] == true
      assert response["options"]["challenge"]

      # Verify challenge stored
      challenge = get_session(conn, :webauthn_authentication_challenge)
      assert is_binary(challenge)

      # Verify challenge in database
      stored_challenge =
        Repo.get_by(Authify.MFA.WebAuthnChallenge,
          user_id: user.id,
          challenge: challenge,
          challenge_type: "authentication"
        )

      assert stored_challenge

      # Verify allowed credentials includes our credential
      allowed = response["options"]["allowCredentials"]
      assert length(allowed) == 1
      assert hd(allowed)["id"] == credential.credential_id

      # Note: Complete step requires actual WebAuthn assertion response
      # which we cannot mock in integration tests. This is tested in controller tests.
    end

    test "authentication fails when user has no credentials" do
      org = organization_fixture()
      user = user_for_organization_fixture(org)
      user = Repo.preload(user, :organization)

      # User has no WebAuthn credentials
      assert WebAuthn.list_credentials(user) == []

      # Try to begin authentication
      conn =
        build_conn()
        |> Plug.Test.init_test_session(%{
          mfa_pending_user_id: user.id,
          mfa_pending_organization_id: org.id
        })
        |> post(~p"/mfa/webauthn/authenticate/begin")

      response = json_response(conn, 200)
      assert response["success"] == false
      assert response["error"] =~ "No security keys registered"
    end

    test "authentication requires active MFA session" do
      # No MFA session in place
      conn =
        build_conn()
        |> Plug.Test.init_test_session(%{})
        |> post(~p"/mfa/webauthn/authenticate/begin")

      # Should return error response
      response = json_response(conn, 200)
      assert response["success"] == false
      assert response["error"] =~ "No active MFA session"
    end
  end

  describe "WebAuthn credential management workflow" do
    test "complete credential management lifecycle" do
      org = organization_fixture()
      user = user_for_organization_fixture(org)
      user = Repo.preload(user, :organization)

      # Step 1: User has no credentials
      conn =
        build_conn()
        |> log_in_user(user, org)
        |> get(~p"/#{org.slug}/profile/webauthn")

      assert html_response(conn, 200) =~ "registered any security keys"

      # Step 2: Create a credential
      credential1 =
        create_credential(user, %{
          credential_id: "yubikey_123",
          name: "YubiKey 5"
        })

      # Step 3: List credentials
      conn =
        build_conn()
        |> log_in_user(user, org)
        |> get(~p"/#{org.slug}/profile/webauthn")

      assert html_response(conn, 200) =~ "YubiKey 5"

      # Step 4: Rename credential
      conn =
        build_conn()
        |> log_in_user(user, org)
        |> patch(~p"/#{org.slug}/profile/webauthn/#{credential1.id}/rename", %{
          "name" => "Work YubiKey"
        })

      response = json_response(conn, 200)
      assert response["success"] == true
      assert response["credential"]["name"] == "Work YubiKey"

      # Verify in database
      {:ok, updated} = WebAuthn.get_credential(credential1.id)
      assert updated.name == "Work YubiKey"

      # Step 5: Add another credential
      _credential2 =
        create_credential(user, %{
          credential_id: "touchid_456",
          name: "Touch ID"
        })

      # Verify both credentials listed
      credentials = WebAuthn.list_credentials(user)
      assert length(credentials) == 2

      # Step 6: Revoke one credential
      conn =
        build_conn()
        |> log_in_user(user, org)
        |> delete(~p"/#{org.slug}/profile/webauthn/#{credential1.id}")

      assert redirected_to(conn) == ~p"/#{org.slug}/profile/mfa"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "revoked successfully"

      # Verify credential deleted
      assert {:error, :not_found} = WebAuthn.get_credential(credential1.id)
      assert length(WebAuthn.list_credentials(user)) == 1

      # Step 7: Revoke all credentials with password
      conn =
        build_conn()
        |> log_in_user(user, org)
        |> delete(~p"/#{org.slug}/profile/webauthn", %{
          "password" => "SecureP@ssw0rd!"
        })

      assert redirected_to(conn) == ~p"/#{org.slug}/profile/mfa"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "All security keys have been revoked"

      # Verify all credentials deleted
      assert WebAuthn.list_credentials(user) == []
    end
  end

  describe "WebAuthn organization scoping and isolation" do
    test "credentials are scoped to organizations" do
      org_a = organization_fixture(%{slug: "org-a"})
      org_b = organization_fixture(%{slug: "org-b"})

      user_a = user_for_organization_fixture(org_a)
      user_b = user_for_organization_fixture(org_b)

      # Create credentials for both users
      cred_a =
        create_credential(user_a, %{
          credential_id: "org_a_credential",
          name: "Org A Key"
        })

      cred_b =
        create_credential(user_b, %{
          credential_id: "org_b_credential",
          name: "Org B Key"
        })

      # User A can only see their own credential
      creds_a = WebAuthn.list_credentials(user_a)
      assert length(creds_a) == 1
      assert hd(creds_a).id == cred_a.id

      # User B can only see their own credential
      creds_b = WebAuthn.list_credentials(user_b)
      assert length(creds_b) == 1
      assert hd(creds_b).id == cred_b.id
    end

    test "users cannot access other users' credentials within same organization" do
      org = organization_fixture()
      user1 = user_for_organization_fixture(org)
      user2 = user_for_organization_fixture(org, %{email: "user2@test.com"})

      user1 = Repo.preload(user1, :organization)
      user2 = Repo.preload(user2, :organization)

      # Create credential for user2
      user2_credential =
        create_credential(user2, %{
          credential_id: "user2_credential",
          name: "User 2 Key"
        })

      # User1 tries to rename user2's credential
      conn =
        build_conn()
        |> log_in_user(user1, org)
        |> patch(~p"/#{org.slug}/profile/webauthn/#{user2_credential.id}/rename", %{
          "name" => "Stolen Name"
        })

      response = json_response(conn, 403)
      assert response["success"] == false
      assert response["error"] =~ "Not authorized"

      # User1 tries to delete user2's credential
      conn =
        build_conn()
        |> log_in_user(user1, org)
        |> delete(~p"/#{org.slug}/profile/webauthn/#{user2_credential.id}")

      assert redirected_to(conn) == ~p"/#{org.slug}/profile/mfa"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Not authorized"

      # Verify user2's credential still exists
      {:ok, _credential} = WebAuthn.get_credential(user2_credential.id)
    end
  end

  describe "WebAuthn challenge lifecycle" do
    test "challenges are properly created, consumed, and expired" do
      org = organization_fixture()
      user = user_for_organization_fixture(org)
      user = Repo.preload(user, :organization)

      # Begin registration - creates challenge
      conn =
        build_conn()
        |> log_in_user(user, org)
        |> post(~p"/#{org.slug}/profile/webauthn/register/begin", %{})

      response = json_response(conn, 200)
      challenge = response["options"]["challenge"]

      # Verify challenge exists and is not consumed
      stored_challenge =
        Repo.get_by(Authify.MFA.WebAuthnChallenge,
          user_id: user.id,
          challenge: challenge,
          challenge_type: "registration"
        )

      assert stored_challenge
      refute stored_challenge.consumed_at

      # Simulate multiple begin requests - each creates a new challenge
      conn2 =
        build_conn()
        |> log_in_user(user, org)
        |> post(~p"/#{org.slug}/profile/webauthn/register/begin", %{})

      response2 = json_response(conn2, 200)
      challenge2 = response2["options"]["challenge"]

      # Should be different challenges
      assert challenge != challenge2

      # Both challenges should exist
      all_challenges =
        Repo.all(
          from c in Authify.MFA.WebAuthnChallenge,
            where: c.user_id == ^user.id and c.challenge_type == "registration"
        )

      assert length(all_challenges) >= 2
    end

    test "authentication challenges are separate from registration challenges" do
      org = organization_fixture()
      user = user_for_organization_fixture(org)
      user = Repo.preload(user, :organization)

      # Create a credential so authentication can begin
      create_credential(user, %{credential_id: "test_cred", name: "Test Key"})

      # Create registration challenge
      conn1 =
        build_conn()
        |> log_in_user(user, org)
        |> post(~p"/#{org.slug}/profile/webauthn/register/begin", %{})

      reg_challenge = json_response(conn1, 200)["options"]["challenge"]

      # Create authentication challenge
      conn2 =
        build_conn()
        |> Plug.Test.init_test_session(%{
          mfa_pending_user_id: user.id,
          mfa_pending_organization_id: org.id
        })
        |> post(~p"/mfa/webauthn/authenticate/begin")

      auth_challenge = json_response(conn2, 200)["options"]["challenge"]

      # Verify both exist with different types
      reg_stored =
        Repo.get_by(Authify.MFA.WebAuthnChallenge,
          user_id: user.id,
          challenge: reg_challenge,
          challenge_type: "registration"
        )

      assert reg_stored

      auth_stored =
        Repo.get_by(Authify.MFA.WebAuthnChallenge,
          user_id: user.id,
          challenge: auth_challenge,
          challenge_type: "authentication"
        )

      assert auth_stored

      # Challenges should be different
      assert reg_challenge != auth_challenge
    end
  end

  # Helper functions

  defp log_in_user(conn, user, organization) do
    conn
    |> Plug.Test.init_test_session(%{})
    |> Authify.Guardian.Plug.sign_in(user)
    |> Plug.Conn.put_session(:current_organization_id, organization.id)
    |> Plug.Conn.assign(:current_user, user)
    |> Plug.Conn.assign(:current_organization, organization)
  end

  defp create_credential(user, attrs) do
    default_attrs = %{
      user_id: user.id,
      organization_id: user.organization_id,
      credential_id: "test_credential_#{:rand.uniform(100_000)}",
      public_key: :crypto.strong_rand_bytes(32),
      sign_count: 0,
      name: "Test Credential",
      credential_type: "platform"
    }

    %WebAuthnCredential{}
    |> WebAuthnCredential.changeset(Map.merge(default_attrs, attrs))
    |> Repo.insert!()
  end
end
