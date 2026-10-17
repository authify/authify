defmodule Authify.SCIM.EmailVerificationTest do
  use Authify.DataCase, async: true

  import Authify.AccountsFixtures

  alias Authify.Configurations
  alias Authify.Repo
  alias Authify.SCIM.Provisioning

  describe "create_user_scim/2 email verification" do
    test "leaves SCIM-provided emails unverified by default" do
      organization = organization_fixture()

      {:ok, user} =
        Provisioning.create_user_scim(scim_user_attrs("work@example.com"), organization.id)

      user = Repo.preload(user, :emails)
      refute Enum.any?(user.emails, & &1.verified_at)
    end

    test "marks every SCIM-provided email verified when the mode is true" do
      organization = organization_fixture()

      {:ok, _} =
        Configurations.set_organization_setting(organization, :scim_email_verification, "true")

      {:ok, user} =
        Provisioning.create_user_scim(
          scim_user_attrs("work@example.com", [%{"value" => "home@example.com", "type" => "home"}]),
          organization.id
        )

      user = Repo.preload(user, :emails)
      assert length(user.emails) == 2
      assert Enum.all?(user.emails, & &1.verified_at)
    end

    test "marks only matching SCIM-provided emails verified in regex mode" do
      organization = organization_fixture()

      {:ok, _} =
        Configurations.set_organization_setting(organization, :scim_email_verification, "regex")

      {:ok, _} =
        Configurations.set_organization_setting(
          organization,
          :scim_email_verification_regex,
          "@corp\\.example\\.com$"
        )

      {:ok, user} =
        Provisioning.create_user_scim(
          scim_user_attrs("alice@corp.example.com", [
            %{"value" => "personal@other.com", "type" => "home"}
          ]),
          organization.id
        )

      emails = Map.new(Repo.preload(user, :emails).emails, &{&1.value, &1})
      assert emails["alice@corp.example.com"].verified_at
      refute emails["personal@other.com"].verified_at
    end
  end

  describe "update_user_emails_scim/2 email verification" do
    test "marks newly added emails verified when the mode is true" do
      organization = organization_fixture()

      {:ok, _} =
        Configurations.set_organization_setting(organization, :scim_email_verification, "true")

      {:ok, user} =
        Provisioning.create_user_scim(scim_user_attrs("work@example.com"), organization.id)

      user = Repo.preload(user, :emails)

      {:ok, updated} =
        Provisioning.update_user_emails_scim(user, [
          %{"value" => "work@example.com", "type" => "work", "primary" => true},
          %{"value" => "home@example.com", "type" => "home"}
        ])

      emails = Map.new(updated.emails, &{&1.value, &1})
      assert emails["home@example.com"].verified_at
    end

    test "leaves newly added emails unverified when the mode is false" do
      organization = organization_fixture()

      {:ok, user} =
        Provisioning.create_user_scim(scim_user_attrs("work@example.com"), organization.id)

      user = Repo.preload(user, :emails)

      {:ok, updated} =
        Provisioning.update_user_emails_scim(user, [
          %{"value" => "work@example.com", "type" => "work", "primary" => true},
          %{"value" => "home@example.com", "type" => "home"}
        ])

      emails = Map.new(updated.emails, &{&1.value, &1})
      refute emails["home@example.com"].verified_at
    end

    test "preserves existing verification when the mode is false" do
      organization = organization_fixture()

      {:ok, user} =
        Provisioning.create_user_scim(scim_user_attrs("work@example.com"), organization.id)

      user = Repo.preload(user, :emails)

      {:ok, _} = verify_email(hd(user.emails))

      {:ok, updated} =
        Provisioning.update_user_emails_scim(user, [
          %{"value" => "work@example.com", "type" => "work", "primary" => true}
        ])

      assert hd(updated.emails).verified_at
    end
  end

  defp verify_email(email) do
    email
    |> Authify.Accounts.UserEmail.verify_changeset()
    |> Repo.update()
  end

  defp scim_user_attrs(primary_email, extra_emails \\ []) do
    %{
      username: "user-#{System.unique_integer()}",
      first_name: "Test",
      last_name: "User",
      active: true,
      emails: [%{"value" => primary_email, "type" => "work", "primary" => true} | extra_emails]
    }
  end
end
