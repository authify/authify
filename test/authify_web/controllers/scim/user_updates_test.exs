defmodule AuthifyWeb.SCIM.UserUpdatesTest do
  use Authify.DataCase, async: true

  alias AuthifyWeb.SCIM.UserUpdates

  doctest AuthifyWeb.SCIM.UserUpdates

  describe "email_like_user_name?/1" do
    test "returns true for email addresses" do
      assert UserUpdates.email_like_user_name?("bjensen@example.com")
    end

    test "returns false for plain usernames" do
      refute UserUpdates.email_like_user_name?("bjensen")
    end

    test "returns false for non-binary values" do
      refute UserUpdates.email_like_user_name?(nil)
    end
  end
end
