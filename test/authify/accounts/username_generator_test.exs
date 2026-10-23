defmodule Authify.Accounts.UsernameGeneratorTest do
  @moduledoc """
  Unit tests for `User.generate_unique_username/3`, including the default-seed
  fallback for seeds that sanitize to an empty string.
  """

  use Authify.DataCase, async: true

  alias Authify.Accounts.User
  alias Authify.Repo
  import Authify.AccountsFixtures

  @username_format ~r/^[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]$/

  describe "generate_unique_username/3" do
    test "returns a usable username for a seed that sanitizes to an empty string" do
      org = organization_fixture()

      username = User.generate_unique_username("!!!", org.id, Repo)

      assert is_binary(username)
      assert String.length(username) >= 3
      assert username =~ @username_format
    end

    test "returns a usable username for a non-binary seed" do
      org = organization_fixture()

      username = User.generate_unique_username(nil, org.id, Repo)

      assert is_binary(username)
      assert String.length(username) >= 3
      assert username =~ @username_format
    end

    test "uniquifies the fallback when the default seed is already taken in the organization" do
      org = organization_fixture()

      _taken =
        user_fixture(%{
          "username" => "user",
          "email" => "taken-user@example.com",
          organization: org
        })

      username = User.generate_unique_username("!!!", org.id, Repo)

      assert is_binary(username)
      assert username != "user"
      assert String.starts_with?(username, "user")
      assert username =~ @username_format
    end
  end
end
