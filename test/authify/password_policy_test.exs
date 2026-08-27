defmodule Authify.PasswordPolicyTest do
  use Authify.DataCase, async: true

  import Authify.AccountsFixtures

  alias Authify.{Accounts, Configurations, PasswordPolicy}

  describe "resolve/1" do
    test "returns strict default policy for nil" do
      policy = PasswordPolicy.resolve(nil)

      assert policy.password_min_length == 8
      assert policy.password_max_length == 100
      assert policy.password_require_uppercase == true
      assert policy.password_require_lowercase == true
      assert policy.password_require_digit == true
      assert policy.password_require_special == true
      assert policy.password_common_blocklist_enabled == true
    end

    test "returns strict default policy when organization has no overrides" do
      org = organization_fixture()
      policy = PasswordPolicy.resolve(org)

      assert policy.password_min_length == 8
      assert policy.password_require_uppercase == true
    end

    test "reflects organization overrides" do
      org = organization_fixture()

      Configurations.get_or_create_configuration("Organization", org.id, "organization")
      {:ok, _} = Configurations.set_setting("Organization", org.id, :password_min_length, 6)

      {:ok, _} =
        Configurations.set_setting("Organization", org.id, :password_require_uppercase, false)

      policy = PasswordPolicy.resolve(org)

      assert policy.password_min_length == 6
      assert policy.password_require_uppercase == false
      assert policy.password_require_special == true
    end
  end

  describe "configurable policy across password entry points" do
    setup do
      org = organization_fixture()
      Configurations.get_or_create_configuration("Organization", org.id, "organization")

      {:ok, _} = Configurations.set_setting("Organization", org.id, :password_min_length, 6)
      {:ok, _} = Configurations.set_setting("Organization", org.id, :password_max_length, 64)

      for setting <- [
            :password_require_uppercase,
            :password_require_lowercase,
            :password_require_digit,
            :password_require_special
          ] do
        {:ok, _} = Configurations.set_setting("Organization", org.id, setting, false)
      end

      {:ok, _} =
        Configurations.set_setting(
          "Organization",
          org.id,
          :password_common_blocklist_enabled,
          false
        )

      %{org: org}
    end

    defp simple_password_attrs(org, password) do
      %{
        "organization_id" => org.id,
        "first_name" => "Jane",
        "last_name" => "Doe",
        "email" => unique_user_email(),
        "password" => password,
        "password_confirmation" => password
      }
    end

    test "allows a simple password on user registration", %{org: org} do
      assert {:ok, _user} = Accounts.create_user(simple_password_attrs(org, "simple1"))
    end

    test "rejects a password shorter than the configured minimum", %{org: org} do
      assert {:error, changeset} = Accounts.create_user(simple_password_attrs(org, "short"))
      assert %{password: ["must be between 6 and 64 characters"]} = errors_on(changeset)
    end

    test "allows a simple password on password change", %{org: org} do
      user = user_for_organization_fixture(org)

      assert {:ok, _user} =
               Accounts.update_user_password(user, %{
                 "password" => "changed1",
                 "password_confirmation" => "changed1"
               })
    end

    test "allows a simple password on password reset", %{org: org} do
      user = user_for_organization_fixture(org)
      {:ok, _user, token} = Accounts.generate_password_reset_token(user)

      assert {:ok, _reset_user} =
               Accounts.reset_password_with_token(token, %{
                 "password" => "resetpw1",
                 "password_confirmation" => "resetpw1"
               })
    end

    test "orgs with default settings still enforce strict policy" do
      strict_org = organization_fixture()
      attrs = simple_password_attrs(strict_org, "simple1")
      assert {:error, changeset} = Accounts.create_user(attrs)
      assert %{password: _} = errors_on(changeset)
    end
  end

  describe "validate_password/2" do
    alias Authify.Accounts.User

    test "default policy rejects weak passwords" do
      policy = PasswordPolicy.default_policy()

      changeset =
        User.changeset(
          %User{},
          %{"password" => "password", "password_confirmation" => "password"},
          policy
        )

      refute changeset.valid?
      assert %{password: [_ | _]} = errors_on(changeset)
    end

    test "lenient policy accepts weak passwords" do
      policy = %{
        password_min_length: 1,
        password_max_length: 100,
        password_require_uppercase: false,
        password_require_lowercase: false,
        password_require_digit: false,
        password_require_special: false,
        password_common_blocklist_enabled: false
      }

      changeset =
        User.changeset(
          %User{},
          %{"password" => "simple", "password_confirmation" => "simple"},
          policy
        )

      assert changeset.valid?
    end
  end

  describe "describe/1" do
    test "lists all requirements for the strict default policy" do
      requirements = PasswordPolicy.describe(PasswordPolicy.default_policy())

      assert "At least 8 characters" in requirements
      assert "At least one uppercase letter (A-Z)" in requirements
      assert "At least one lowercase letter (a-z)" in requirements
      assert "At least one number (0-9)" in requirements
      assert "At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)" in requirements
    end

    test "omits disabled requirements" do
      policy = %{
        password_min_length: 6,
        password_max_length: 64,
        password_require_uppercase: false,
        password_require_lowercase: false,
        password_require_digit: false,
        password_require_special: false,
        password_common_blocklist_enabled: false
      }

      requirements = PasswordPolicy.describe(policy)

      assert requirements == ["At least 6 characters"]
    end
  end
end
