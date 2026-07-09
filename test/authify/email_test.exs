defmodule Authify.EmailTest do
  use Authify.DataCase, async: true

  import Swoosh.TestAssertions
  import Authify.AccountsFixtures

  alias Authify.Email

  defp create_invitation(organization, inviter, attrs \\ %{}) do
    {:ok, invitation} =
      attrs
      |> Enum.into(%{
        "email" => "invitee@example.com",
        "role" => "user",
        "organization_id" => organization.id,
        "invited_by_id" => inviter.id
      })
      |> Authify.Accounts.create_invitation()

    Authify.Repo.preload(invitation, [:organization, invited_by: [:emails]])
  end

  describe "invitation_email/2" do
    test "html body contains accept URL, organization name, and role" do
      organization = organization_fixture()
      inviter = admin_user_fixture(organization)

      invitation = create_invitation(organization, inviter, %{"role" => "admin"})

      accept_url = "https://example.com/accept/456"
      email = Email.invitation_email(invitation, accept_url)

      assert email.subject == "You've been invited to join #{organization.name} on Authify"
      assert email.html_body =~ accept_url
      assert email.html_body =~ organization.name
      assert email.html_body =~ "Admin"
      assert email.html_body =~ "Accept Invitation"
    end

    test "text body contains key content" do
      organization = organization_fixture()
      inviter = admin_user_fixture(organization)

      invitation = create_invitation(organization, inviter)

      accept_url = "https://example.com/accept/789"
      email = Email.invitation_email(invitation, accept_url)

      assert email.text_body =~ accept_url
      assert email.text_body =~ organization.name
      assert email.text_body =~ "User"
    end
  end

  describe "password_reset_email/2" do
    test "html body contains reset URL and security notice" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      reset_url = "https://example.com/reset/def"
      email = Email.password_reset_email(user, reset_url)

      assert email.subject == "Password Reset Request - #{organization.name}"
      assert email.html_body =~ reset_url
      assert email.html_body =~ "Reset Password"
      assert email.html_body =~ "Security Notice"
    end

    test "text body contains reset URL and expiry notice" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      reset_url = "https://example.com/reset/ghi"
      email = Email.password_reset_email(user, reset_url)

      assert email.text_body =~ reset_url
      assert email.text_body =~ "expires in 24 hours"
    end
  end

  describe "email_verification_email/2" do
    test "html body contains verification URL and button" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      verify_url = "https://example.com/verify/123"
      email = Email.email_verification_email(user, verify_url)

      assert email.subject == "Please verify your email - #{organization.name}"
      assert email.html_body =~ verify_url
      assert email.html_body =~ "Verify Email"
      assert email.html_body =~ "expires in 24 hours"
    end
  end

  describe "send functions" do
    test "send_invitation_email/2 delivers in test mode" do
      organization = organization_fixture()
      inviter = admin_user_fixture(organization)

      invitation = create_invitation(organization, inviter)

      assert {:ok, _} = Email.send_invitation_email(invitation, "https://example.com/accept/1")
    end

    test "send_email_verification_email/2 delivers in test mode" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      assert {:ok, _} = Email.send_email_verification_email(user, "https://example.com/verify/1")
    end

    test "send_password_reset_email/2 delivers in test mode" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      assert {:ok, _} = Email.send_password_reset_email(user, "https://example.com/reset/1")
    end
  end

  describe "format_datetime/1" do
    test "formats a datetime as a date string" do
      organization = organization_fixture()
      inviter = admin_user_fixture(organization)

      expires_at = DateTime.new!(~D[2026-12-25], ~T[00:00:00], "Etc/UTC")

      invitation = create_invitation(organization, inviter, %{"expires_at" => expires_at})

      email = Email.invitation_email(invitation, "https://example.com/accept/1")

      assert email.html_body =~ "2026-12-25"
      assert email.text_body =~ "2026-12-25"
    end
  end

  describe "email footer" do
    test "invitation footer includes contact email link" do
      organization = organization_fixture()
      inviter = admin_user_fixture(organization)

      invitation = create_invitation(organization, inviter)

      email = Email.invitation_email(invitation, "https://example.com/accept/1")

      inviter_email = Authify.Accounts.User.get_primary_email_value(inviter)
      assert email.html_body =~ "mailto:#{inviter_email}"
    end

    test "password reset footer uses generic admin contact message" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      email = Email.password_reset_email(user, "https://example.com/reset/1")

      assert email.html_body =~ "contact your organization administrator"
      refute email.html_body =~ "mailto:"
    end
  end

  describe "shared layout" do
    test "all email types include the shared CSS and header" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      inviter = admin_user_fixture(organization)

      invitation = create_invitation(organization, inviter)

      invitation_email = Email.invitation_email(invitation, "https://example.com/accept/1")
      reset_email = Email.password_reset_email(user, "https://example.com/reset/1")
      verify_email = Email.email_verification_email(user, "https://example.com/verify/1")

      for email <- [invitation_email, reset_email, verify_email] do
        assert email.html_body =~ "<!DOCTYPE html>"
        assert email.html_body =~ "font-family: -apple-system"
        assert email.html_body =~ "border-bottom: 2px solid #0d6efd"
        assert email.html_body =~ "Authify</h1>"
        assert email.html_body =~ "class=\"footer\""
      end
    end
  end
end
