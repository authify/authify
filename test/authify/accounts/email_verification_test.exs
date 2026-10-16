defmodule Authify.Accounts.EmailVerificationTest do
  @moduledoc false
  # async: false so Oban's inline testing mode runs the verification tasks
  # synchronously against the shared sandbox connection.
  use Authify.DataCase, async: false

  alias Authify.Accounts
  alias Authify.Accounts.User

  import Authify.AccountsFixtures

  test "create_user_and_send_verification/3 generates a verification token" do
    organization = organization_fixture()

    attrs = %{
      "first_name" => "New",
      "last_name" => "User",
      "emails" => [%{"value" => "new-user@example.com", "primary" => true, "type" => "work"}],
      "password" => "SecureP@ssw0rd!",
      "password_confirmation" => "SecureP@ssw0rd!",
      "organization_id" => organization.id
    }

    {:ok, user} = Accounts.create_user_and_send_verification(attrs, organization.id, "user")

    primary_email =
      user
      |> Authify.Repo.preload(:emails, force: true)
      |> User.get_primary_email()

    # The verification workflow generated a token, and the email is unverified
    assert primary_email.verification_token
    refute primary_email.verified_at
  end

  test "create_organization_with_admin/2 generates a verification token for the admin" do
    n = System.unique_integer([:positive])

    {:ok, {_organization, admin}} =
      Accounts.create_organization_with_admin(
        %{name: "Verify Org #{n}", slug: "verify-org-#{n}"},
        %{
          "first_name" => "Admin",
          "last_name" => "User",
          "emails" => [
            %{"value" => "admin-#{n}@example.com", "primary" => true, "type" => "work"}
          ],
          "password" => "SecureP@ssw0rd!",
          "password_confirmation" => "SecureP@ssw0rd!"
        }
      )

    primary_email =
      admin
      |> Authify.Repo.preload(:emails, force: true)
      |> User.get_primary_email()

    assert primary_email.verification_token
    refute primary_email.verified_at
  end
end
