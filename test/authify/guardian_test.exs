defmodule Authify.GuardianTest do
  use Authify.DataCase, async: true

  import Authify.AccountsFixtures

  alias Authify.Accounts
  alias Authify.Guardian

  describe "session version claims" do
    test "tokens carry the user's session version" do
      user = user_fixture()

      assert {:ok, _token, claims} = Guardian.encode_and_sign(user)
      assert claims["ver"] == user.session_version
    end

    test "tokens verify while the session version is unchanged" do
      user = user_fixture()

      assert {:ok, token, _claims} = Guardian.encode_and_sign(user)
      assert {:ok, _claims} = Guardian.decode_and_verify(token)
    end

    test "tokens are rejected after the session version is bumped" do
      user = user_fixture()

      assert {:ok, token, _claims} = Guardian.encode_and_sign(user)

      assert {:ok, _user} = Accounts.revoke_user_sessions(user)

      assert {:error, :session_revoked} = Guardian.decode_and_verify(token)
    end

    test "a token issued after a bump is accepted" do
      user = user_fixture()

      assert {:ok, _token, _claims} = Guardian.encode_and_sign(user)
      {:ok, updated_user} = Accounts.revoke_user_sessions(user)

      # Reload to mirror what resource_from_claims would return.
      refreshed_user = Accounts.get_user!(updated_user.id)

      assert {:ok, fresh_token, _claims} = Guardian.encode_and_sign(refreshed_user)
      assert {:ok, _claims} = Guardian.decode_and_verify(fresh_token)
    end
  end
end
