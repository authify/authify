defmodule Authify.OAuth.AuthorizationCodeTest do
  @moduledoc false
  use Authify.DataCase, async: true

  alias Authify.OAuth.AuthorizationCode

  import Authify.AccountsFixtures
  import Authify.OAuthFixtures

  describe "changeset/2" do
    setup do
      org = organization_fixture()
      user = user_for_organization_fixture(org)
      app = application_fixture(organization: org)
      %{user: user, app: app}
    end

    test "valid changeset without PKCE", %{user: user, app: app} do
      attrs = %{
        redirect_uri: "https://example.com/callback",
        scopes: "openid profile",
        application_id: app.id,
        user_id: user.id
      }

      changeset = AuthorizationCode.changeset(%AuthorizationCode{}, attrs)
      assert changeset.valid?
    end

    test "requires redirect_uri", %{user: user, app: app} do
      attrs = %{scopes: "openid", application_id: app.id, user_id: user.id}
      changeset = AuthorizationCode.changeset(%AuthorizationCode{}, attrs)
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).redirect_uri
    end

    test "requires scopes", %{user: user, app: app} do
      attrs = %{
        redirect_uri: "https://example.com/callback",
        application_id: app.id,
        user_id: user.id
      }

      changeset = AuthorizationCode.changeset(%AuthorizationCode{}, attrs)
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).scopes
    end

    test "requires application_id", %{user: user} do
      attrs = %{redirect_uri: "https://example.com/callback", scopes: "openid", user_id: user.id}
      changeset = AuthorizationCode.changeset(%AuthorizationCode{}, attrs)
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).application_id
    end

    test "requires user_id", %{app: app} do
      attrs = %{
        redirect_uri: "https://example.com/callback",
        scopes: "openid",
        application_id: app.id
      }

      changeset = AuthorizationCode.changeset(%AuthorizationCode{}, attrs)
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).user_id
    end

    test "auto-generates a code", %{user: user, app: app} do
      attrs = %{
        redirect_uri: "https://example.com/callback",
        scopes: "openid",
        application_id: app.id,
        user_id: user.id
      }

      changeset = AuthorizationCode.changeset(%AuthorizationCode{}, attrs)
      assert changeset.valid?
      code = Ecto.Changeset.get_change(changeset, :code)
      assert is_binary(code)
      assert byte_size(code) > 0
    end

    test "auto-generates expires_at approximately 10 minutes from now", %{user: user, app: app} do
      attrs = %{
        redirect_uri: "https://example.com/callback",
        scopes: "openid",
        application_id: app.id,
        user_id: user.id
      }

      changeset = AuthorizationCode.changeset(%AuthorizationCode{}, attrs)
      expires_at = Ecto.Changeset.get_change(changeset, :expires_at)
      assert %DateTime{} = expires_at
      diff = DateTime.diff(expires_at, DateTime.utc_now(), :second)
      assert diff > 600 - 5
      assert diff <= 600
    end

    test "accepts S256 PKCE", %{user: user, app: app} do
      verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

      challenge =
        :crypto.hash(:sha256, verifier)
        |> Base.url_encode64(padding: false)

      attrs = %{
        redirect_uri: "https://example.com/callback",
        scopes: "openid",
        application_id: app.id,
        user_id: user.id,
        code_challenge: challenge,
        code_challenge_method: "S256"
      }

      changeset = AuthorizationCode.changeset(%AuthorizationCode{}, attrs)
      assert changeset.valid?
    end

    test "accepts plain PKCE", %{user: user, app: app} do
      attrs = %{
        redirect_uri: "https://example.com/callback",
        scopes: "openid",
        application_id: app.id,
        user_id: user.id,
        code_challenge: "my_plain_verifier",
        code_challenge_method: "plain"
      }

      changeset = AuthorizationCode.changeset(%AuthorizationCode{}, attrs)
      assert changeset.valid?
    end

    test "defaults code_challenge_method to plain when only challenge is provided", %{
      user: user,
      app: app
    } do
      attrs = %{
        redirect_uri: "https://example.com/callback",
        scopes: "openid",
        application_id: app.id,
        user_id: user.id,
        code_challenge: "my_challenge"
      }

      changeset = AuthorizationCode.changeset(%AuthorizationCode{}, attrs)
      assert changeset.valid?
      assert Ecto.Changeset.get_change(changeset, :code_challenge_method) == "plain"
    end

    test "rejects invalid code_challenge_method", %{user: user, app: app} do
      attrs = %{
        redirect_uri: "https://example.com/callback",
        scopes: "openid",
        application_id: app.id,
        user_id: user.id,
        code_challenge: "some_challenge",
        code_challenge_method: "RS256"
      }

      changeset = AuthorizationCode.changeset(%AuthorizationCode{}, attrs)
      refute changeset.valid?
      assert "must be S256 or plain" in errors_on(changeset).code_challenge_method
    end
  end

  describe "expired?/1" do
    test "returns false when expires_at is in the future" do
      code = %AuthorizationCode{expires_at: DateTime.utc_now() |> DateTime.add(600, :second)}
      refute AuthorizationCode.expired?(code)
    end

    test "returns true when expires_at is in the past" do
      code = %AuthorizationCode{expires_at: DateTime.utc_now() |> DateTime.add(-1, :second)}
      assert AuthorizationCode.expired?(code)
    end
  end

  describe "used?/1" do
    test "returns false when used_at is nil" do
      code = %AuthorizationCode{used_at: nil}
      refute AuthorizationCode.used?(code)
    end

    test "returns true when used_at is set" do
      code = %AuthorizationCode{used_at: DateTime.utc_now()}
      assert AuthorizationCode.used?(code)
    end
  end

  describe "valid_for_exchange?/1" do
    test "returns true when not expired and not used" do
      code = %AuthorizationCode{
        expires_at: DateTime.utc_now() |> DateTime.add(600, :second),
        used_at: nil
      }

      assert AuthorizationCode.valid_for_exchange?(code)
    end

    test "returns false when expired" do
      code = %AuthorizationCode{
        expires_at: DateTime.utc_now() |> DateTime.add(-1, :second),
        used_at: nil
      }

      refute AuthorizationCode.valid_for_exchange?(code)
    end

    test "returns false when already used" do
      code = %AuthorizationCode{
        expires_at: DateTime.utc_now() |> DateTime.add(600, :second),
        used_at: DateTime.utc_now()
      }

      refute AuthorizationCode.valid_for_exchange?(code)
    end

    test "returns false when both expired and used" do
      code = %AuthorizationCode{
        expires_at: DateTime.utc_now() |> DateTime.add(-1, :second),
        used_at: DateTime.utc_now()
      }

      refute AuthorizationCode.valid_for_exchange?(code)
    end
  end

  describe "mark_as_used/1" do
    test "puts a used_at timestamp on the changeset" do
      changeset = Ecto.Changeset.change(%AuthorizationCode{})
      result = AuthorizationCode.mark_as_used(changeset)
      assert %DateTime{} = Ecto.Changeset.get_change(result, :used_at)
    end
  end

  describe "scopes_list/1" do
    test "splits space-separated scopes into a list" do
      code = %AuthorizationCode{scopes: "openid profile email"}
      assert AuthorizationCode.scopes_list(code) == ["openid", "profile", "email"]
    end

    test "returns empty list when scopes is nil" do
      assert AuthorizationCode.scopes_list(%AuthorizationCode{scopes: nil}) == []
    end

    test "ignores extra spaces" do
      code = %AuthorizationCode{scopes: " openid  profile "}
      result = AuthorizationCode.scopes_list(code)
      assert "openid" in result
      assert "profile" in result
      refute "" in result
    end
  end

  describe "verify_pkce/2" do
    test "returns true when no PKCE was used (nil challenge)" do
      code = %AuthorizationCode{code_challenge: nil, code_challenge_method: nil}
      assert AuthorizationCode.verify_pkce(code, nil)
      assert AuthorizationCode.verify_pkce(code, "any_verifier")
    end

    test "returns true for a valid S256 verifier" do
      verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
      challenge = :crypto.hash(:sha256, verifier) |> Base.url_encode64(padding: false)

      code = %AuthorizationCode{
        code_challenge: challenge,
        code_challenge_method: "S256"
      }

      assert AuthorizationCode.verify_pkce(code, verifier)
    end

    test "returns false for an invalid S256 verifier" do
      challenge =
        :crypto.hash(:sha256, "correct_verifier") |> Base.url_encode64(padding: false)

      code = %AuthorizationCode{
        code_challenge: challenge,
        code_challenge_method: "S256"
      }

      refute AuthorizationCode.verify_pkce(code, "wrong_verifier")
    end

    test "returns true for a valid plain verifier" do
      verifier = "my_plain_code_verifier"

      code = %AuthorizationCode{
        code_challenge: verifier,
        code_challenge_method: "plain"
      }

      assert AuthorizationCode.verify_pkce(code, verifier)
    end

    test "returns false for an invalid plain verifier" do
      code = %AuthorizationCode{
        code_challenge: "correct_verifier",
        code_challenge_method: "plain"
      }

      refute AuthorizationCode.verify_pkce(code, "wrong_verifier")
    end

    test "returns false when verifier is nil but challenge is set" do
      code = %AuthorizationCode{
        code_challenge: "some_challenge",
        code_challenge_method: "S256"
      }

      refute AuthorizationCode.verify_pkce(code, nil)
    end
  end
end
