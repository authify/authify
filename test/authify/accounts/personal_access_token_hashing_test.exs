defmodule Authify.Accounts.PersonalAccessTokenHashingTest do
  use Authify.DataCase, async: true

  alias Authify.Accounts
  alias Authify.Accounts.PersonalAccessToken

  import Authify.AccountsFixtures

  describe "token hashing" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      %{organization: organization, user: user}
    end

    test "creates PAT with hashed token", %{user: user, organization: organization} do
      {:ok, token} =
        Accounts.create_personal_access_token(user, organization, %{
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
        Accounts.create_personal_access_token(user, organization, %{
          "name" => "Test Token",
          "scopes" => ["users:read"]
        })

      plaintext_token = token.plaintext_token

      # Reload from database
      reloaded_token = Accounts.get_personal_access_token!(token.id, user)

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
        Accounts.create_personal_access_token(user, organization, %{
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
      {:ok, authenticated_token} = Accounts.authenticate_personal_access_token(plaintext_token)

      assert authenticated_token.user.id == user.id
      assert authenticated_token.name == "Auth Test Token"
    end

    test "fails authentication with wrong token", %{} do
      wrong_token = "authify_pat_wrongtokenwrongtokenwrongtokenwron"

      assert {:error, :invalid_token} = Accounts.authenticate_personal_access_token(wrong_token)
    end

    test "fails authentication with hashed token (not plaintext)", %{token: token} do
      # Trying to authenticate with the hash should fail
      assert {:error, :invalid_token} = Accounts.authenticate_personal_access_token(token.token)
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
                 Accounts.authenticate_personal_access_token(invalid_token)
      end
    end

    test "fails authentication with expired token", %{
      user: user,
      organization: organization
    } do
      # Create an expired token
      {:ok, expired_token} =
        Accounts.create_personal_access_token(user, organization, %{
          "name" => "Expired Token",
          "scopes" => ["users:read"],
          "expires_at" => DateTime.utc_now() |> DateTime.add(-1, :day)
        })

      plaintext = expired_token.plaintext_token

      # Should fail authentication
      assert {:error, :invalid_token} = Accounts.authenticate_personal_access_token(plaintext)
    end

    test "fails authentication with inactive token", %{
      user: user,
      organization: organization
    } do
      # Create an inactive token
      {:ok, inactive_token} =
        Accounts.create_personal_access_token(user, organization, %{
          "name" => "Inactive Token",
          "scopes" => ["users:read"],
          "is_active" => false
        })

      plaintext = inactive_token.plaintext_token

      # Should fail authentication
      assert {:error, :invalid_token} = Accounts.authenticate_personal_access_token(plaintext)
    end

    test "updates last_used_at on successful authentication", %{
      plaintext_token: plaintext_token,
      token: token,
      user: user
    } do
      # Initial last_used_at should be nil
      assert is_nil(token.last_used_at)

      # Authenticate
      {:ok, _authenticated_token} = Accounts.authenticate_personal_access_token(plaintext_token)

      # Reload and check last_used_at
      reloaded = Accounts.get_personal_access_token!(token.id, user)
      assert reloaded.last_used_at
      assert DateTime.diff(reloaded.last_used_at, DateTime.utc_now(), :second) < 5
    end
  end
end
