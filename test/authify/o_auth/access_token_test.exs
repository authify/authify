defmodule Authify.OAuth.AccessTokenTest do
  @moduledoc false
  use Authify.DataCase, async: true

  alias Authify.OAuth.AccessToken

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
      changeset = AccessToken.changeset(%AccessToken{}, attrs)
      assert changeset.valid?
    end

    test "requires scopes", %{user: user, app: app} do
      attrs = %{application_id: app.id, user_id: user.id}
      changeset = AccessToken.changeset(%AccessToken{}, attrs)
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).scopes
    end

    test "requires application_id", %{user: user} do
      attrs = %{scopes: "openid", user_id: user.id}
      changeset = AccessToken.changeset(%AccessToken{}, attrs)
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).application_id
    end

    test "requires user_id", %{app: app} do
      attrs = %{scopes: "openid", application_id: app.id}
      changeset = AccessToken.changeset(%AccessToken{}, attrs)
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).user_id
    end

    test "auto-generates a token", %{user: user, app: app} do
      attrs = %{scopes: "openid", application_id: app.id, user_id: user.id}
      changeset = AccessToken.changeset(%AccessToken{}, attrs)
      assert changeset.valid?
      token = Ecto.Changeset.get_change(changeset, :token)
      assert is_binary(token)
      assert byte_size(token) > 0
    end

    test "generates a different token on each call", %{user: user, app: app} do
      attrs = %{scopes: "openid", application_id: app.id, user_id: user.id}
      cs1 = AccessToken.changeset(%AccessToken{}, attrs)
      cs2 = AccessToken.changeset(%AccessToken{}, attrs)
      refute Ecto.Changeset.get_change(cs1, :token) == Ecto.Changeset.get_change(cs2, :token)
    end

    test "auto-generates expires_at approximately 1 hour from now", %{user: user, app: app} do
      attrs = %{scopes: "openid", application_id: app.id, user_id: user.id}
      changeset = AccessToken.changeset(%AccessToken{}, attrs)
      expires_at = Ecto.Changeset.get_change(changeset, :expires_at)
      assert %DateTime{} = expires_at
      diff = DateTime.diff(expires_at, DateTime.utc_now(), :second)
      assert diff > 3600 - 5
      assert diff <= 3600
    end
  end

  describe "management_api_changeset/2" do
    setup do
      org = organization_fixture()
      app = management_api_application_fixture(organization: org)
      %{app: app}
    end

    test "valid without user_id", %{app: app} do
      attrs = %{scopes: "users:read", application_id: app.id}
      changeset = AccessToken.management_api_changeset(%AccessToken{}, attrs)
      assert changeset.valid?
    end

    test "requires scopes", %{app: app} do
      attrs = %{application_id: app.id}
      changeset = AccessToken.management_api_changeset(%AccessToken{}, attrs)
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).scopes
    end

    test "requires application_id" do
      attrs = %{scopes: "users:read"}
      changeset = AccessToken.management_api_changeset(%AccessToken{}, attrs)
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).application_id
    end

    test "auto-generates token and expires_at", %{app: app} do
      attrs = %{scopes: "users:read", application_id: app.id}
      changeset = AccessToken.management_api_changeset(%AccessToken{}, attrs)
      assert changeset.valid?
      assert is_binary(Ecto.Changeset.get_change(changeset, :token))
      assert %DateTime{} = Ecto.Changeset.get_change(changeset, :expires_at)
    end
  end

  describe "expired?/1" do
    test "returns false when expires_at is in the future" do
      token = %AccessToken{expires_at: DateTime.utc_now() |> DateTime.add(3600, :second)}
      refute AccessToken.expired?(token)
    end

    test "returns true when expires_at is in the past" do
      token = %AccessToken{expires_at: DateTime.utc_now() |> DateTime.add(-1, :second)}
      assert AccessToken.expired?(token)
    end
  end

  describe "revoked?/1" do
    test "returns false when revoked_at is nil" do
      token = %AccessToken{revoked_at: nil}
      refute AccessToken.revoked?(token)
    end

    test "returns true when revoked_at is set" do
      token = %AccessToken{revoked_at: DateTime.utc_now()}
      assert AccessToken.revoked?(token)
    end
  end

  describe "valid?/1" do
    test "returns true when not expired and not revoked" do
      token = %AccessToken{
        expires_at: DateTime.utc_now() |> DateTime.add(3600, :second),
        revoked_at: nil
      }

      assert AccessToken.valid?(token)
    end

    test "returns false when expired" do
      token = %AccessToken{
        expires_at: DateTime.utc_now() |> DateTime.add(-1, :second),
        revoked_at: nil
      }

      refute AccessToken.valid?(token)
    end

    test "returns false when revoked" do
      token = %AccessToken{
        expires_at: DateTime.utc_now() |> DateTime.add(3600, :second),
        revoked_at: DateTime.utc_now()
      }

      refute AccessToken.valid?(token)
    end

    test "returns false when both expired and revoked" do
      token = %AccessToken{
        expires_at: DateTime.utc_now() |> DateTime.add(-1, :second),
        revoked_at: DateTime.utc_now()
      }

      refute AccessToken.valid?(token)
    end
  end

  describe "revoke/1" do
    test "puts a revoked_at timestamp on the changeset" do
      changeset = Ecto.Changeset.change(%AccessToken{})
      result = AccessToken.revoke(changeset)
      assert %DateTime{} = Ecto.Changeset.get_change(result, :revoked_at)
    end
  end

  describe "scopes_list/1" do
    test "splits space-separated scopes into a list" do
      token = %AccessToken{scopes: "openid profile email"}
      assert AccessToken.scopes_list(token) == ["openid", "profile", "email"]
    end

    test "returns a single-element list for a single scope" do
      token = %AccessToken{scopes: "openid"}
      assert AccessToken.scopes_list(token) == ["openid"]
    end

    test "returns empty list when scopes is nil" do
      assert AccessToken.scopes_list(%AccessToken{scopes: nil}) == []
    end

    test "ignores extra spaces between scopes" do
      token = %AccessToken{scopes: " openid  profile "}
      result = AccessToken.scopes_list(token)
      assert "openid" in result
      assert "profile" in result
      refute "" in result
    end
  end
end
