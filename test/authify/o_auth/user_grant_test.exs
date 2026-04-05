defmodule Authify.OAuth.UserGrantTest do
  @moduledoc false
  use Authify.DataCase, async: true

  alias Authify.OAuth.UserGrant

  import Authify.AccountsFixtures
  import Authify.OAuthFixtures

  describe "changeset/2" do
    setup do
      org = organization_fixture()
      user = user_for_organization_fixture(org)
      app = application_fixture(organization: org)

      %{org: org, user: user, app: app}
    end

    test "valid changeset with required fields", %{user: user, app: app} do
      attrs = %{
        user_id: user.id,
        application_id: app.id,
        scopes: "openid profile email"
      }

      changeset = UserGrant.changeset(%UserGrant{}, attrs)

      assert changeset.valid?
      assert get_change(changeset, :user_id) == user.id
      assert get_change(changeset, :application_id) == app.id
      assert get_change(changeset, :scopes) == "openid profile email"
    end

    test "requires user_id" do
      attrs = %{
        application_id: 1,
        scopes: "openid"
      }

      changeset = UserGrant.changeset(%UserGrant{}, attrs)

      refute changeset.valid?
      assert %{user_id: ["can't be blank"]} = errors_on(changeset)
    end

    test "requires application_id" do
      attrs = %{
        user_id: 1,
        scopes: "openid"
      }

      changeset = UserGrant.changeset(%UserGrant{}, attrs)

      refute changeset.valid?
      assert %{application_id: ["can't be blank"]} = errors_on(changeset)
    end

    test "requires scopes" do
      attrs = %{
        user_id: 1,
        application_id: 1
      }

      changeset = UserGrant.changeset(%UserGrant{}, attrs)

      refute changeset.valid?
      assert %{scopes: ["can't be blank"]} = errors_on(changeset)
    end

    test "validates scopes cannot be empty string" do
      attrs = %{
        user_id: 1,
        application_id: 1,
        scopes: "   "
      }

      changeset = UserGrant.changeset(%UserGrant{}, attrs)

      refute changeset.valid?
      # Trimmed whitespace is treated as empty, which triggers "cannot be empty" error
      errors = errors_on(changeset)
      assert errors[:scopes] in [["cannot be empty"], ["can't be blank"]]
    end

    test "allows revoked_at to be nil" do
      attrs = %{
        user_id: 1,
        application_id: 1,
        scopes: "openid"
      }

      changeset = UserGrant.changeset(%UserGrant{}, attrs)

      assert changeset.valid?
      assert get_change(changeset, :revoked_at) == nil
    end

    test "allows revoked_at to be a datetime" do
      revoked_time = DateTime.utc_now() |> DateTime.truncate(:second)

      attrs = %{
        user_id: 1,
        application_id: 1,
        scopes: "openid",
        revoked_at: revoked_time
      }

      changeset = UserGrant.changeset(%UserGrant{}, attrs)

      assert changeset.valid?
      assert get_change(changeset, :revoked_at) == revoked_time
    end
  end

  describe "scopes_list/1" do
    test "parses space-separated scopes string" do
      grant = %UserGrant{scopes: "openid profile email"}

      assert UserGrant.scopes_list(grant) == ["openid", "profile", "email"]
    end

    test "handles single scope" do
      grant = %UserGrant{scopes: "openid"}

      assert UserGrant.scopes_list(grant) == ["openid"]
    end

    test "filters out empty strings from extra spaces" do
      grant = %UserGrant{scopes: "openid  profile   email"}

      assert UserGrant.scopes_list(grant) == ["openid", "profile", "email"]
    end

    test "returns empty list for empty string" do
      grant = %UserGrant{scopes: ""}

      assert UserGrant.scopes_list(grant) == []
    end

    test "returns empty list for nil" do
      assert UserGrant.scopes_list(nil) == []
    end
  end

  describe "scopes_match?/2" do
    test "returns true when all requested scopes are granted" do
      grant = %UserGrant{scopes: "openid profile email"}

      assert UserGrant.scopes_match?(grant, ["openid", "profile"])
      assert UserGrant.scopes_match?(grant, ["openid"])
      assert UserGrant.scopes_match?(grant, ["openid", "profile", "email"])
    end

    test "returns false when some requested scopes are not granted" do
      grant = %UserGrant{scopes: "openid profile"}

      refute UserGrant.scopes_match?(grant, ["openid", "profile", "email"])
      refute UserGrant.scopes_match?(grant, ["email"])
    end

    test "returns false for empty grant" do
      grant = %UserGrant{scopes: ""}

      refute UserGrant.scopes_match?(grant, ["openid"])
    end

    test "returns true for empty requested scopes" do
      grant = %UserGrant{scopes: "openid profile"}

      assert UserGrant.scopes_match?(grant, [])
    end

    test "returns false for non-grant input" do
      refute UserGrant.scopes_match?(nil, ["openid"])
      refute UserGrant.scopes_match?("not a grant", ["openid"])
    end
  end

  describe "revoked?/1" do
    test "returns false when revoked_at is nil" do
      grant = %UserGrant{revoked_at: nil}

      refute UserGrant.revoked?(grant)
    end

    test "returns true when revoked_at is set" do
      grant = %UserGrant{revoked_at: DateTime.utc_now()}

      assert UserGrant.revoked?(grant)
    end
  end

  describe "revoke/1" do
    test "sets revoked_at timestamp" do
      grant = %UserGrant{revoked_at: nil}
      changeset = Ecto.Changeset.change(grant)

      revoked_changeset = UserGrant.revoke(changeset)

      refute is_nil(Ecto.Changeset.get_change(revoked_changeset, :revoked_at))
    end

    test "sets revoked_at to current time" do
      before_time = DateTime.utc_now() |> DateTime.add(-1, :second)

      grant = %UserGrant{revoked_at: nil}
      changeset = Ecto.Changeset.change(grant)
      revoked_changeset = UserGrant.revoke(changeset)

      revoked_at = Ecto.Changeset.get_change(revoked_changeset, :revoked_at)

      after_time = DateTime.utc_now() |> DateTime.add(1, :second)

      assert DateTime.compare(revoked_at, before_time) == :gt
      assert DateTime.compare(revoked_at, after_time) == :lt
    end
  end
end
