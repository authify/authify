defmodule Authify.Accounts.UserEmailTest do
  @moduledoc false
  use Authify.DataCase, async: true

  alias Authify.Accounts.UserEmail

  import Authify.AccountsFixtures

  describe "changeset/2" do
    setup do
      org = organization_fixture()
      user = user_for_organization_fixture(org)
      %{user: user}
    end

    test "valid with email address and user_id", %{user: user} do
      changeset =
        UserEmail.changeset(%UserEmail{}, %{value: "valid@example.com", user_id: user.id})

      assert changeset.valid?
    end

    test "requires value", %{user: user} do
      changeset = UserEmail.changeset(%UserEmail{}, %{user_id: user.id})
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).value
    end

    test "requires user_id" do
      changeset = UserEmail.changeset(%UserEmail{}, %{value: "valid@example.com"})
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).user_id
    end

    test "rejects email missing @" do
      changeset = UserEmail.changeset(%UserEmail{}, %{value: "notanemail", user_id: 1})
      refute changeset.valid?
      assert "has invalid format" in errors_on(changeset).value
    end

    test "rejects email missing domain extension" do
      changeset = UserEmail.changeset(%UserEmail{}, %{value: "user@nodot", user_id: 1})
      refute changeset.valid?
      assert "has invalid format" in errors_on(changeset).value
    end

    test "rejects email with whitespace" do
      changeset = UserEmail.changeset(%UserEmail{}, %{value: "user @example.com", user_id: 1})
      refute changeset.valid?
      assert "has invalid format" in errors_on(changeset).value
    end

    test "rejects email exceeding 160 characters", %{user: user} do
      long_email = String.duplicate("a", 150) <> "@example.com"
      changeset = UserEmail.changeset(%UserEmail{}, %{value: long_email, user_id: user.id})
      refute changeset.valid?
      assert "should be at most 160 character(s)" in errors_on(changeset).value
    end

    test "validates type inclusion - accepts work, home, other", %{user: user} do
      for type <- ["work", "home", "other"] do
        changeset =
          UserEmail.changeset(%UserEmail{}, %{
            value: "test@example.com",
            user_id: user.id,
            type: type
          })

        assert changeset.valid?, "expected type #{type} to be valid"
      end
    end

    test "rejects invalid type", %{user: user} do
      changeset =
        UserEmail.changeset(%UserEmail{}, %{
          value: "test@example.com",
          user_id: user.id,
          type: "personal"
        })

      refute changeset.valid?
      assert "is invalid" in errors_on(changeset).type
    end

    test "defaults type to work when not specified", %{user: user} do
      changeset =
        UserEmail.changeset(%UserEmail{}, %{value: "test@example.com", user_id: user.id})

      # Default is set on the schema, not the changeset change
      assert Ecto.Changeset.get_field(changeset, :type) == "work"
    end
  end

  describe "nested_changeset/2" do
    test "valid without user_id" do
      changeset = UserEmail.nested_changeset(%UserEmail{}, %{value: "nested@example.com"})
      assert changeset.valid?
    end

    test "requires value" do
      changeset = UserEmail.nested_changeset(%UserEmail{}, %{})
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).value
    end

    test "rejects invalid email format" do
      changeset = UserEmail.nested_changeset(%UserEmail{}, %{value: "not-an-email"})
      refute changeset.valid?
      assert "has invalid format" in errors_on(changeset).value
    end

    test "validates type inclusion" do
      changeset =
        UserEmail.nested_changeset(%UserEmail{}, %{value: "test@example.com", type: "invalid"})

      refute changeset.valid?
      assert "is invalid" in errors_on(changeset).type
    end
  end

  describe "verify_changeset/1" do
    test "sets verified_at to a current timestamp" do
      email = %UserEmail{
        verification_token: "some_token",
        verification_expires_at: DateTime.utc_now()
      }

      changeset = UserEmail.verify_changeset(email)
      verified_at = Ecto.Changeset.get_change(changeset, :verified_at)
      assert %DateTime{} = verified_at
      assert DateTime.diff(DateTime.utc_now(), verified_at, :second) < 2
    end

    test "clears the verification_token" do
      email = %UserEmail{verification_token: "some_hashed_token"}
      changeset = UserEmail.verify_changeset(email)
      assert Ecto.Changeset.get_change(changeset, :verification_token) == nil
    end

    test "clears the verification_expires_at" do
      email = %UserEmail{
        verification_expires_at: DateTime.utc_now() |> DateTime.add(3600, :second)
      }

      changeset = UserEmail.verify_changeset(email)
      assert Ecto.Changeset.get_change(changeset, :verification_expires_at) == nil
    end
  end

  describe "verification_token_changeset/2" do
    test "stores a SHA-256 hash of the token (not the plaintext)" do
      email = %UserEmail{}
      plaintext_token = "my_verification_token"
      changeset = UserEmail.verification_token_changeset(email, plaintext_token)

      stored_token = Ecto.Changeset.get_change(changeset, :verification_token)
      expected_hash = :crypto.hash(:sha256, plaintext_token) |> Base.encode16(case: :lower)

      assert stored_token == expected_hash
      refute stored_token == plaintext_token
    end

    test "sets verification_expires_at approximately 24 hours from now" do
      changeset = UserEmail.verification_token_changeset(%UserEmail{}, "some_token")
      expires_at = Ecto.Changeset.get_change(changeset, :verification_expires_at)
      assert %DateTime{} = expires_at
      diff = DateTime.diff(expires_at, DateTime.utc_now(), :second)
      assert diff > 24 * 3600 - 5
      assert diff <= 24 * 3600
    end

    test "different tokens produce different stored hashes" do
      cs1 = UserEmail.verification_token_changeset(%UserEmail{}, "token_one")
      cs2 = UserEmail.verification_token_changeset(%UserEmail{}, "token_two")

      hash1 = Ecto.Changeset.get_change(cs1, :verification_token)
      hash2 = Ecto.Changeset.get_change(cs2, :verification_token)
      refute hash1 == hash2
    end
  end
end
