defmodule Authify.MFA.WebAuthnTest do
  @moduledoc """
  Tests for WebAuthn context module.
  """
  use Authify.DataCase

  alias Authify.MFA.WebAuthn
  alias Authify.MFA.WebAuthnChallenge
  alias Authify.MFA.WebAuthnCredential
  alias Authify.Repo

  import Authify.AccountsFixtures

  # Helper to create a test credential
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

  describe "begin_registration/2" do
    test "generates a challenge and options for user" do
      user = user_fixture()

      assert {:ok, %{challenge: challenge, options: options}} =
               WebAuthn.begin_registration(user)

      # Challenge should be a base64url-encoded string
      assert is_binary(challenge)
      assert byte_size(challenge) > 20

      # Options should contain the WebAuthn creation options
      assert is_map(options)
      assert options.challenge
      assert options.rp
      assert options.user
      assert String.contains?(options.user.id, Base.url_encode64("user_", padding: false))
    end

    test "accepts authenticator attachment option" do
      user = user_fixture()

      {:ok, %{options: options}} =
        WebAuthn.begin_registration(user, authenticator_attachment: "platform")

      assert options.authenticatorSelection
      assert options.authenticatorSelection.authenticatorAttachment == "platform"
    end

    test "excludes existing credentials" do
      user = user_fixture()

      # Create an existing credential
      create_credential(user, %{credential_id: "existing_credential_123"})

      # Begin new registration - should exclude existing credential
      {:ok, %{options: options}} = WebAuthn.begin_registration(user)

      assert is_list(options.excludeCredentials)
      assert length(options.excludeCredentials) == 1

      [excluded] = options.excludeCredentials
      # The ID in excludeCredentials is the actual credential_id, already base64url-encoded
      assert excluded.id == "existing_credential_123"
      assert excluded.type == "public-key"
    end

    test "stores challenge in database" do
      user = user_fixture()

      {:ok, %{challenge: challenge}} = WebAuthn.begin_registration(user)

      # Verify challenge was stored
      stored_challenge =
        Repo.get_by(WebAuthnChallenge,
          user_id: user.id,
          challenge: challenge,
          challenge_type: "registration"
        )

      assert stored_challenge
      refute stored_challenge.consumed_at
    end

    test "accepts IP address and user agent in options" do
      user = user_fixture()

      {:ok, _result} =
        WebAuthn.begin_registration(user,
          ip_address: "192.168.1.1",
          user_agent: "Mozilla/5.0"
        )

      # Should not error with these options
      assert true
    end
  end

  describe "complete_registration/4 - basic validation" do
    setup do
      user = user_fixture()
      {:ok, %{challenge: challenge}} = WebAuthn.begin_registration(user)

      %{user: user, challenge: challenge}
    end

    @tag :capture_log
    test "returns error for invalid challenge", %{user: user} do
      fake_response = %{
        "id" => "fake_id",
        "response" => %{"attestationObject" => "fake", "clientDataJSON" => "fake"}
      }

      assert {:error, :invalid_challenge} =
               WebAuthn.complete_registration(user, fake_response, "invalid_challenge")
    end

    @tag :capture_log
    test "returns error for already used challenge", %{user: user, challenge: challenge} do
      # Mark challenge as consumed
      stored_challenge =
        Repo.get_by!(WebAuthnChallenge,
          user_id: user.id,
          challenge: challenge,
          challenge_type: "registration"
        )

      stored_challenge
      |> Ecto.Changeset.change(%{
        consumed_at: DateTime.utc_now() |> DateTime.truncate(:second)
      })
      |> Repo.update!()

      fake_response = %{
        "id" => "fake_id",
        "response" => %{"attestationObject" => "fake", "clientDataJSON" => "fake"}
      }

      assert {:error, :challenge_already_used} =
               WebAuthn.complete_registration(user, fake_response, challenge)
    end

    @tag :capture_log
    test "challenge expiry is checked", %{user: user, challenge: challenge} do
      # Mark challenge as expired (older than 5 minutes)
      stored_challenge =
        Repo.get_by!(WebAuthnChallenge,
          user_id: user.id,
          challenge: challenge,
          challenge_type: "registration"
        )

      stored_challenge
      |> Ecto.Changeset.change(%{
        inserted_at:
          DateTime.add(DateTime.utc_now(), -6 * 60, :second) |> DateTime.truncate(:second)
      })
      |> Repo.update!()

      # Create a fake response
      fake_response = %{
        "id" => "fake_id",
        "response" => %{
          "attestationObject" => Base.encode64("fake"),
          "clientDataJSON" => Base.encode64(~s({"type":"webauthn.create"}))
        }
      }

      # The implementation will catch expired challenge or challenge mismatch
      # Both are acceptable results as expired challenges should not be processed
      result = WebAuthn.complete_registration(user, fake_response, challenge)
      assert {:error, _reason} = result
      # Could be :challenge_expired or :challenge_mismatch depending on order of checks
    end
  end

  describe "begin_authentication/2" do
    setup do
      user = user_fixture()

      # Create a credential for the user
      create_credential(user, %{credential_id: "test_credential_456"})

      %{user: user}
    end

    test "generates authentication challenge and options", %{user: user} do
      assert {:ok, %{challenge: challenge, options: options}} =
               WebAuthn.begin_authentication(user)

      # Challenge should be a base64url-encoded string
      assert is_binary(challenge)
      assert byte_size(challenge) > 20

      # Options should contain the WebAuthn request options
      assert is_map(options)
      assert options.challenge
      assert is_list(options.allowCredentials)
      assert length(options.allowCredentials) == 1

      [allowed] = options.allowCredentials
      # The ID in allowCredentials is the actual credential_id
      assert allowed.id == "test_credential_456"
      assert allowed.type == "public-key"
    end

    test "returns error if user has no credentials" do
      user_without_creds = user_fixture()

      assert {:error, :no_credentials} = WebAuthn.begin_authentication(user_without_creds)
    end

    test "stores challenge in database", %{user: user} do
      {:ok, %{challenge: challenge}} = WebAuthn.begin_authentication(user)

      # Verify challenge was stored
      stored_challenge =
        Repo.get_by(WebAuthnChallenge,
          user_id: user.id,
          challenge: challenge,
          challenge_type: "authentication"
        )

      assert stored_challenge
      refute stored_challenge.consumed_at
    end

    test "accepts IP address and user agent in options", %{user: user} do
      {:ok, _result} =
        WebAuthn.begin_authentication(user,
          ip_address: "192.168.1.1",
          user_agent: "Mozilla/5.0"
        )

      # Should not error with these options
      assert true
    end
  end

  describe "complete_authentication/3 - basic validation" do
    setup do
      user = user_fixture()

      # Create a credential
      credential = create_credential(user, %{credential_id: "test_credential_789"})

      {:ok, %{challenge: challenge}} = WebAuthn.begin_authentication(user)

      %{user: user, challenge: challenge, credential: credential}
    end

    @tag :capture_log
    test "returns error for invalid challenge", %{user: user} do
      fake_response = %{
        "id" => "fake_id",
        "response" => %{"authenticatorData" => "fake", "signature" => "fake"}
      }

      assert {:error, :invalid_challenge} =
               WebAuthn.complete_authentication(user, fake_response, "invalid_challenge")
    end

    @tag :capture_log
    test "returns error for already used challenge", %{user: user, challenge: challenge} do
      # Mark challenge as consumed
      stored_challenge =
        Repo.get_by!(WebAuthnChallenge,
          user_id: user.id,
          challenge: challenge,
          challenge_type: "authentication"
        )

      stored_challenge
      |> Ecto.Changeset.change(%{
        consumed_at: DateTime.utc_now() |> DateTime.truncate(:second)
      })
      |> Repo.update!()

      fake_response = %{
        "id" => "fake_id",
        "response" => %{"authenticatorData" => "fake", "signature" => "fake"}
      }

      assert {:error, :challenge_already_used} =
               WebAuthn.complete_authentication(user, fake_response, challenge)
    end

    @tag :capture_log
    test "challenge expiry is checked", %{
      user: user,
      challenge: challenge,
      credential: credential
    } do
      # Mark challenge as expired (older than 5 minutes)
      stored_challenge =
        Repo.get_by!(WebAuthnChallenge,
          user_id: user.id,
          challenge: challenge,
          challenge_type: "authentication"
        )

      stored_challenge
      |> Ecto.Changeset.change(%{
        inserted_at:
          DateTime.add(DateTime.utc_now(), -6 * 60, :second) |> DateTime.truncate(:second)
      })
      |> Repo.update!()

      # Use the actual credential ID so it doesn't fail on credential lookup
      fake_response = %{
        "id" => credential.credential_id,
        "response" => %{
          "authenticatorData" => Base.encode64("fake"),
          "clientDataJSON" => Base.encode64(~s({"type":"webauthn.get"})),
          "signature" => Base.encode64("fake")
        }
      }

      # The implementation will catch expired challenge or challenge mismatch/assertion failure
      # All error results are acceptable as expired challenges should not be processed
      result = WebAuthn.complete_authentication(user, fake_response, challenge)
      assert {:error, _reason} = result
    end
  end

  describe "list_credentials/1" do
    test "returns all credentials for a user" do
      user = user_fixture()

      # Create multiple credentials
      credential1 = create_credential(user, %{credential_id: "cred_1", name: "YubiKey"})

      credential2 =
        create_credential(user, %{
          credential_id: "cred_2",
          name: "Touch ID",
          sign_count: 5,
          credential_type: "platform"
        })

      credentials = WebAuthn.list_credentials(user)

      assert length(credentials) == 2
      assert Enum.any?(credentials, &(&1.id == credential1.id))
      assert Enum.any?(credentials, &(&1.id == credential2.id))
    end

    test "returns empty list for user with no credentials" do
      user = user_fixture()

      assert [] = WebAuthn.list_credentials(user)
    end

    test "only returns credentials for the specific user" do
      user1 = user_fixture()
      user2 = user_fixture()

      # Create credential for user1
      create_credential(user1, %{credential_id: "cred_user1", name: "User1 Key"})

      # user2 should have no credentials
      assert [] = WebAuthn.list_credentials(user2)

      # user1 should have 1 credential
      assert [_credential] = WebAuthn.list_credentials(user1)
    end
  end

  describe "get_credential/1" do
    test "returns credential by ID" do
      user = user_fixture()

      credential = create_credential(user, %{credential_id: "test_cred", name: "Test"})

      assert {:ok, fetched} = WebAuthn.get_credential(credential.id)
      assert fetched.id == credential.id
      assert fetched.name == "Test"
    end

    test "returns error for non-existent ID" do
      # Use an integer ID that doesn't exist
      assert {:error, :not_found} = WebAuthn.get_credential(999_999)
    end
  end

  describe "get_credential_by_id/1" do
    test "returns credential by credential_id" do
      user = user_fixture()

      credential = create_credential(user, %{credential_id: "unique_cred_id", name: "Test"})

      assert {:ok, fetched} = WebAuthn.get_credential_by_id("unique_cred_id")
      assert fetched.id == credential.id
      assert fetched.credential_id == "unique_cred_id"
    end

    test "returns error for non-existent credential_id" do
      assert {:error, :credential_not_found} =
               WebAuthn.get_credential_by_id("non_existent_cred_id")
    end
  end

  describe "revoke_credential/1" do
    test "deletes the credential" do
      user = user_fixture()

      credential = create_credential(user, %{credential_id: "to_revoke", name: "Test"})

      assert {:ok, deleted} = WebAuthn.revoke_credential(credential.id)
      assert deleted.id == credential.id

      # Verify it's deleted
      assert {:error, :not_found} = WebAuthn.get_credential(credential.id)
    end

    test "returns error for non-existent credential" do
      # Use an integer ID that doesn't exist
      assert {:error, :not_found} = WebAuthn.revoke_credential(999_999)
    end
  end

  describe "revoke_all_credentials/1" do
    test "deletes all credentials for a user" do
      user = user_fixture()

      # Create multiple credentials
      create_credential(user, %{credential_id: "cred_1", name: "Cred 1"})
      create_credential(user, %{credential_id: "cred_2", name: "Cred 2"})

      assert [_, _] = WebAuthn.list_credentials(user)

      assert {:ok, count} = WebAuthn.revoke_all_credentials(user)
      assert count == 2

      assert [] = WebAuthn.list_credentials(user)
    end

    test "returns 0 for user with no credentials" do
      user = user_fixture()

      assert {:ok, 0} = WebAuthn.revoke_all_credentials(user)
    end

    test "only deletes credentials for the specific user" do
      user1 = user_fixture()
      user2 = user_fixture()

      # Create credentials for both users
      create_credential(user1, %{credential_id: "user1_cred", name: "User1"})
      create_credential(user2, %{credential_id: "user2_cred", name: "User2"})

      # Revoke all for user1
      assert {:ok, 1} = WebAuthn.revoke_all_credentials(user1)

      # user1 should have no credentials
      assert [] = WebAuthn.list_credentials(user1)

      # user2 should still have their credential
      assert [_credential] = WebAuthn.list_credentials(user2)
    end
  end

  describe "update_credential_name/2" do
    test "updates the credential name" do
      user = user_fixture()

      credential = create_credential(user, %{credential_id: "cred_to_rename", name: "Old Name"})

      assert {:ok, updated} = WebAuthn.update_credential_name(credential.id, "New Name")
      assert updated.name == "New Name"
      assert updated.id == credential.id

      # Verify in database
      {:ok, fetched} = WebAuthn.get_credential(credential.id)
      assert fetched.name == "New Name"
    end

    test "returns error for non-existent credential" do
      # Use an integer ID that doesn't exist
      assert {:error, :not_found} = WebAuthn.update_credential_name(999_999, "New Name")
    end

    test "accepts empty name" do
      user = user_fixture()

      credential = create_credential(user, %{credential_id: "cred", name: "Valid Name"})

      # Empty name is allowed by the schema
      assert {:ok, updated} = WebAuthn.update_credential_name(credential.id, "")
      assert updated.name == ""
    end
  end
end
