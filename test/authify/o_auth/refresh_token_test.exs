defmodule Authify.OAuth.RefreshTokenTest do
  @moduledoc false
  use Authify.DataCase, async: true

  alias Authify.OAuth.RefreshToken

  import Authify.AccountsFixtures
  import Authify.OAuthFixtures

  describe "changeset/2" do
    setup do
      org = organization_fixture()
      user = user_for_organization_fixture(org)
      app = application_fixture(organization: org)
      %{user: user, app: app}
    end

    test "valid changeset with required fields", %{user: user, app: app} do
      attrs = %{scopes: "openid profile", application_id: app.id, user_id: user.id}
      changeset = RefreshToken.changeset(%RefreshToken{}, attrs)
      assert changeset.valid?
    end

    test "requires scopes", %{user: user, app: app} do
      attrs = %{application_id: app.id, user_id: user.id}
      changeset = RefreshToken.changeset(%RefreshToken{}, attrs)
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).scopes
    end

    test "requires application_id", %{user: user} do
      attrs = %{scopes: "openid", user_id: user.id}
      changeset = RefreshToken.changeset(%RefreshToken{}, attrs)
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).application_id
    end

    test "requires user_id", %{app: app} do
      attrs = %{scopes: "openid", application_id: app.id}
      changeset = RefreshToken.changeset(%RefreshToken{}, attrs)
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).user_id
    end

    test "auto-generates a hashed token when none provided", %{user: user, app: app} do
      attrs = %{scopes: "openid", application_id: app.id, user_id: user.id}
      changeset = RefreshToken.changeset(%RefreshToken{}, attrs)
      assert changeset.valid?
      token_hash = Ecto.Changeset.get_change(changeset, :token)
      assert is_binary(token_hash)
      assert byte_size(token_hash) > 0
    end

    test "also stores plaintext_token as a virtual field", %{user: user, app: app} do
      attrs = %{scopes: "openid", application_id: app.id, user_id: user.id}
      changeset = RefreshToken.changeset(%RefreshToken{}, attrs)
      plaintext = Ecto.Changeset.get_change(changeset, :plaintext_token)
      assert is_binary(plaintext)
      assert byte_size(plaintext) > 0
    end

    test "stored token is the SHA-256 hash of the plaintext token", %{user: user, app: app} do
      attrs = %{scopes: "openid", application_id: app.id, user_id: user.id}
      changeset = RefreshToken.changeset(%RefreshToken{}, attrs)
      plaintext = Ecto.Changeset.get_change(changeset, :plaintext_token)
      token_hash = Ecto.Changeset.get_change(changeset, :token)
      assert RefreshToken.hash_token(plaintext) == token_hash
    end

    test "auto-generates expires_at approximately 30 days from now", %{user: user, app: app} do
      attrs = %{scopes: "openid", application_id: app.id, user_id: user.id}
      changeset = RefreshToken.changeset(%RefreshToken{}, attrs)
      expires_at = Ecto.Changeset.get_change(changeset, :expires_at)
      assert %DateTime{} = expires_at
      diff = DateTime.diff(expires_at, DateTime.utc_now(), :second)
      # Should be approximately 30 days (within 60 seconds tolerance)
      assert diff > 30 * 24 * 60 * 60 - 60
      assert diff <= 30 * 24 * 60 * 60
    end

    test "preserves an explicit expires_at when provided", %{user: user, app: app} do
      custom_expires =
        DateTime.utc_now() |> DateTime.add(7 * 24 * 3600, :second) |> DateTime.truncate(:second)

      attrs = %{
        scopes: "openid",
        application_id: app.id,
        user_id: user.id,
        expires_at: custom_expires
      }

      changeset = RefreshToken.changeset(%RefreshToken{}, attrs)
      assert Ecto.Changeset.get_change(changeset, :expires_at) == custom_expires
    end
  end

  describe "expired?/1" do
    test "returns false when expires_at is in the future" do
      token = %RefreshToken{expires_at: DateTime.utc_now() |> DateTime.add(3600, :second)}
      refute RefreshToken.expired?(token)
    end

    test "returns true when expires_at is in the past" do
      token = %RefreshToken{expires_at: DateTime.utc_now() |> DateTime.add(-1, :second)}
      assert RefreshToken.expired?(token)
    end
  end

  describe "revoked?/1" do
    test "returns false when revoked_at is nil" do
      token = %RefreshToken{revoked_at: nil}
      refute RefreshToken.revoked?(token)
    end

    test "returns true when revoked_at is set" do
      token = %RefreshToken{revoked_at: DateTime.utc_now()}
      assert RefreshToken.revoked?(token)
    end
  end

  describe "valid?/1" do
    test "returns true when not expired and not revoked" do
      token = %RefreshToken{
        expires_at: DateTime.utc_now() |> DateTime.add(3600, :second),
        revoked_at: nil
      }

      assert RefreshToken.valid?(token)
    end

    test "returns false when expired" do
      token = %RefreshToken{
        expires_at: DateTime.utc_now() |> DateTime.add(-1, :second),
        revoked_at: nil
      }

      refute RefreshToken.valid?(token)
    end

    test "returns false when revoked" do
      token = %RefreshToken{
        expires_at: DateTime.utc_now() |> DateTime.add(3600, :second),
        revoked_at: DateTime.utc_now()
      }

      refute RefreshToken.valid?(token)
    end

    test "returns false when both expired and revoked" do
      token = %RefreshToken{
        expires_at: DateTime.utc_now() |> DateTime.add(-1, :second),
        revoked_at: DateTime.utc_now()
      }

      refute RefreshToken.valid?(token)
    end
  end

  describe "revoke/1" do
    test "puts a revoked_at timestamp on the changeset" do
      changeset = Ecto.Changeset.change(%RefreshToken{})
      result = RefreshToken.revoke(changeset)
      assert %DateTime{} = Ecto.Changeset.get_change(result, :revoked_at)
    end
  end

  describe "scopes_list/1" do
    test "splits space-separated scopes into a list" do
      token = %RefreshToken{scopes: "openid profile email"}
      assert RefreshToken.scopes_list(token) == ["openid", "profile", "email"]
    end

    test "returns a single-element list for a single scope" do
      token = %RefreshToken{scopes: "openid"}
      assert RefreshToken.scopes_list(token) == ["openid"]
    end

    test "returns empty list when scopes is nil" do
      assert RefreshToken.scopes_list(%RefreshToken{scopes: nil}) == []
    end

    test "ignores leading/trailing spaces" do
      token = %RefreshToken{scopes: " openid  profile "}
      result = RefreshToken.scopes_list(token)
      assert "openid" in result
      assert "profile" in result
      refute "" in result
    end
  end

  describe "hash_token/1" do
    test "returns a base64-encoded string" do
      hash = RefreshToken.hash_token("some_plaintext_token")
      assert is_binary(hash)
      assert String.match?(hash, ~r/^[A-Za-z0-9+\/]+=*$/)
    end

    test "is deterministic for the same input" do
      hash1 = RefreshToken.hash_token("my_token")
      hash2 = RefreshToken.hash_token("my_token")
      assert hash1 == hash2
    end

    test "produces different hashes for different inputs" do
      hash1 = RefreshToken.hash_token("token_a")
      hash2 = RefreshToken.hash_token("token_b")
      refute hash1 == hash2
    end
  end

  describe "verify_token/2" do
    test "returns true when plaintext matches the stored hash" do
      plaintext = "my_secret_refresh_token"
      hash = RefreshToken.hash_token(plaintext)
      assert RefreshToken.verify_token(plaintext, hash)
    end

    test "returns false when plaintext does not match the stored hash" do
      hash = RefreshToken.hash_token("correct_token")
      refute RefreshToken.verify_token("wrong_token", hash)
    end

    test "returns false when either argument is nil" do
      refute RefreshToken.verify_token(nil, "some_hash")
      refute RefreshToken.verify_token("some_token", nil)
      refute RefreshToken.verify_token(nil, nil)
    end
  end
end
