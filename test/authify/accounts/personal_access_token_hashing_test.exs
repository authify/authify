defmodule Authify.Accounts.PersonalAccessTokenHashingTest do
  use Authify.DataCase, async: true

  alias Authify.Accounts.PersonalAccessToken
  alias Authify.PersonalAccessTokens

  import Authify.AccountsFixtures

  describe "token hashing" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      %{organization: organization, user: user}
    end

    test "creates PAT with hashed token", %{user: user, organization: organization} do
      {:ok, token} =
        PersonalAccessTokens.create_personal_access_token(user, organization, %{
          "name" => "Test Token",
          "scopes" => ["users:read", "users:write"]
        })

      # Should have a plaintext_token (virtual field)
      assert token.plaintext_token
      assert String.starts_with?(token.plaintext_token, "authify_pat_")

      # Should have a hashed token in the database
      assert token.token
      refute token.token == token.plaintext_token

      # Token should be base64-encoded hash
      assert String.match?(token.token, ~r/^[A-Za-z0-9+\/]+=*$/)
    end

    test "plaintext token is not stored in database", %{user: user, organization: organization} do
      {:ok, token} =
        PersonalAccessTokens.create_personal_access_token(user, organization, %{
          "name" => "Test Token",
          "scopes" => ["users:read"]
        })

      plaintext_token = token.plaintext_token

      # Reload from database
      reloaded_token = PersonalAccessTokens.get_personal_access_token!(token.id, user)

      # Plaintext token should not be in database
      assert is_nil(reloaded_token.plaintext_token)

      # But the hash should still be there
      assert reloaded_token.token == token.token

      # And we should be able to verify the plaintext token
      assert PersonalAccessToken.verify_token(plaintext_token, reloaded_token.token)
    end

    test "hash_token/1 produces consistent hashes", %{} do
      token = "authify_pat_test123"

      hash1 = PersonalAccessToken.hash_token(token)
      hash2 = PersonalAccessToken.hash_token(token)

      # Same input should produce same hash
      assert hash1 == hash2
    end

    test "hash_token/1 produces different hashes for different tokens", %{} do
      token1 = "authify_pat_test123"
      token2 = "authify_pat_test456"

      hash1 = PersonalAccessToken.hash_token(token1)
      hash2 = PersonalAccessToken.hash_token(token2)

      # Different inputs should produce different hashes
      refute hash1 == hash2
    end

    test "verify_token/2 returns true for matching token", %{} do
      token = "authify_pat_test123"
      hash = PersonalAccessToken.hash_token(token)

      assert PersonalAccessToken.verify_token(token, hash) == true
    end

    test "verify_token/2 returns false for non-matching token", %{} do
      token1 = "authify_pat_test123"
      token2 = "authify_pat_test456"
      hash1 = PersonalAccessToken.hash_token(token1)

      assert PersonalAccessToken.verify_token(token2, hash1) == false
    end

    test "verify_token/2 handles nil values", %{} do
      assert PersonalAccessToken.verify_token(nil, "hash") == false
      assert PersonalAccessToken.verify_token("token", nil) == false
      assert PersonalAccessToken.verify_token(nil, nil) == false
    end
  end

  describe "authentication with hashed tokens" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      {:ok, token} =
        PersonalAccessTokens.create_personal_access_token(user, organization, %{
          "name" => "Auth Test Token",
          "scopes" => ["users:read", "users:write"]
        })

      %{
        organization: organization,
        user: user,
        token: token,
        plaintext_token: token.plaintext_token
      }
    end

    test "authenticates with valid plaintext token", %{
      plaintext_token: plaintext_token,
      user: user
    } do
      {:ok, authenticated_token} =
        PersonalAccessTokens.authenticate_personal_access_token(plaintext_token)

      assert authenticated_token.user.id == user.id
      assert authenticated_token.name == "Auth Test Token"
    end

    test "fails authentication with wrong token", %{} do
      wrong_token = "authify_pat_wrongtokenwrongtokenwrongtokenwron"

      assert {:error, :invalid_token} =
               PersonalAccessTokens.authenticate_personal_access_token(wrong_token)
    end

    test "fails authentication with hashed token (not plaintext)", %{token: token} do
      # Trying to authenticate with the hash should fail
      assert {:error, :invalid_token} =
               PersonalAccessTokens.authenticate_personal_access_token(token.token)
    end

    test "fails authentication with invalid format", %{} do
      invalid_tokens = [
        "not_a_valid_token",
        "authify_wrong_format",
        "",
        "Bearer authify_pat_test"
      ]

      for invalid_token <- invalid_tokens do
        assert {:error, :invalid_token} =
                 PersonalAccessTokens.authenticate_personal_access_token(invalid_token)
      end
    end

    test "fails authentication with expired token", %{
      user: user,
      organization: organization
    } do
      # Create an expired token
      {:ok, expired_token} =
        PersonalAccessTokens.create_personal_access_token(user, organization, %{
          "name" => "Expired Token",
          "scopes" => ["users:read"],
          "expires_at" => DateTime.utc_now() |> DateTime.add(-1, :day)
        })

      plaintext = expired_token.plaintext_token

      # Should fail authentication
      assert {:error, :invalid_token} =
               PersonalAccessTokens.authenticate_personal_access_token(plaintext)
    end

    test "fails authentication with inactive token", %{
      user: user,
      organization: organization
    } do
      # Create an inactive token
      {:ok, inactive_token} =
        PersonalAccessTokens.create_personal_access_token(user, organization, %{
          "name" => "Inactive Token",
          "scopes" => ["users:read"],
          "is_active" => false
        })

      plaintext = inactive_token.plaintext_token

      # Should fail authentication
      assert {:error, :invalid_token} =
               PersonalAccessTokens.authenticate_personal_access_token(plaintext)
    end

    test "updates last_used_at on successful authentication", %{
      plaintext_token: plaintext_token,
      token: token,
      user: user
    } do
      # Initial last_used_at should be nil
      assert is_nil(token.last_used_at)

      # Authenticate
      {:ok, _authenticated_token} =
        PersonalAccessTokens.authenticate_personal_access_token(plaintext_token)

      # Reload and check last_used_at
      reloaded = PersonalAccessTokens.get_personal_access_token!(token.id, user)
      assert reloaded.last_used_at
      assert DateTime.diff(reloaded.last_used_at, DateTime.utc_now(), :second) < 5
    end
  end

  describe "revoke_all_for_user/1" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      other_user = user_for_organization_fixture(organization)
      %{organization: organization, user: user, other_user: other_user}
    end

    test "deactivates all of the user's active tokens", %{
      organization: organization,
      user: user,
      other_user: other_user
    } do
      {:ok, active1} =
        PersonalAccessTokens.create_personal_access_token(user, organization, %{
          "name" => "Token 1",
          "scopes" => ["users:read"]
        })

      {:ok, active2} =
        PersonalAccessTokens.create_personal_access_token(user, organization, %{
          "name" => "Token 2",
          "scopes" => ["users:read", "users:write"]
        })

      {:ok, other} =
        PersonalAccessTokens.create_personal_access_token(other_user, organization, %{
          "name" => "Other Token",
          "scopes" => ["users:read"]
        })

      assert deactivated = PersonalAccessTokens.revoke_all_for_user(user)
      assert deactivated == 2

      # Reloaded tokens are inactive.
      refute PersonalAccessTokens.get_personal_access_token!(active1.id, user).is_active
      refute PersonalAccessTokens.get_personal_access_token!(active2.id, user).is_active

      # A token owned by another user is untouched and still authenticates.
      assert PersonalAccessTokens.get_personal_access_token!(other.id, other_user).is_active

      assert {:ok, _} =
               PersonalAccessTokens.authenticate_personal_access_token(other.plaintext_token)
    end

    test "skips already-inactive tokens", %{organization: organization, user: user} do
      {:ok, inactive} =
        PersonalAccessTokens.create_personal_access_token(user, organization, %{
          "name" => "Inactive",
          "scopes" => ["users:read"],
          "is_active" => false
        })

      {:ok, active} =
        PersonalAccessTokens.create_personal_access_token(user, organization, %{
          "name" => "Active",
          "scopes" => ["users:read"]
        })

      assert PersonalAccessTokens.revoke_all_for_user(user) == 1

      assert PersonalAccessTokens.get_personal_access_token!(active.id, user).is_active == false
      refute PersonalAccessTokens.get_personal_access_token!(inactive.id, user).is_active
    end

    test "is a no-op for a user with no tokens", %{user: user} do
      assert PersonalAccessTokens.revoke_all_for_user(user) == 0
    end
  end
end
