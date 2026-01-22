defmodule AuthifyWeb.ProfileControllerTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  alias Authify.Accounts
  alias Authify.Accounts.PersonalAccessToken
  alias Authify.Accounts.User
  alias Authify.Accounts.UserEmail
  alias Authify.AuditLog

  setup :register_and_log_in_user

  describe "profile" do
    test "successful profile update logs audit event", %{conn: conn, user: user} do
      params = %{
        "first_name" => "Updated",
        "last_name" => "User",
        "username" => user.username
      }

      conn =
        patch(conn, ~p"/#{user.organization.slug}/profile", %{
          "user" => params
        })

      assert redirected_to(conn) == ~p"/#{user.organization.slug}/profile"

      events =
        AuditLog.list_events(
          organization_id: user.organization_id,
          event_type: "user_updated"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "success"
      assert event.metadata["source"] == "web"
      assert event.metadata["user_id"] == user.id

      assert Enum.any?(event.metadata["changes"], fn change ->
               change["field"] == "first_name" && change["new"] == "Updated"
             end)
    end

    test "failed profile update logs failure", %{conn: conn, user: user} do
      # Try to update with invalid username format (starts with -, not allowed)
      conn =
        patch(conn, ~p"/#{user.organization.slug}/profile", %{
          "user" => %{
            "first_name" => user.first_name,
            "username" => "-invalid"
          }
        })

      assert html_response(conn, 200)

      events =
        AuditLog.list_events(
          organization_id: user.organization_id,
          event_type: "user_updated"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "failure"
      assert event.metadata["source"] == "web"
      assert Enum.any?(event.metadata["errors"], &String.contains?(&1, "username"))
    end
  end

  describe "password" do
    test "successful password update logs audit event", %{conn: conn, user: user} do
      params = %{
        "current_password" => "SecureP@ssw0rd!",
        "password" => "NewP@ss1word!",
        "password_confirmation" => "NewP@ss1word!"
      }

      conn =
        patch(conn, ~p"/#{user.organization.slug}/profile/password", %{
          "user" => params
        })

      assert redirected_to(conn) == ~p"/#{user.organization.slug}/profile"

      events =
        AuditLog.list_events(
          organization_id: user.organization_id,
          event_type: "password_changed"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "success"
      assert event.metadata["source"] == "web"
      assert event.metadata["method"] == "self_service"
      assert event.metadata["user_id"] == user.id
    end

    test "invalid current password logs failure", %{conn: conn, user: user} do
      params = %{
        "current_password" => "wrong-password",
        "password" => "AnotherP@ss1!",
        "password_confirmation" => "AnotherP@ss1!"
      }

      conn =
        patch(conn, ~p"/#{user.organization.slug}/profile/password", %{
          "user" => params
        })

      assert html_response(conn, 200)

      events =
        AuditLog.list_events(
          organization_id: user.organization_id,
          event_type: "password_changed"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "failure"
      assert event.metadata["source"] == "web"
      assert Enum.any?(event.metadata["errors"], &String.contains?(&1, "current_password"))
    end
  end

  describe "email verification resend" do
    test "successful resend logs audit event", %{conn: conn, user: user} do
      # Ensure user is unverified
      user = Authify.Repo.preload(user, :emails)
      primary_email = Authify.Accounts.User.get_primary_email(user)

      {:ok, _reset_email} =
        Authify.Accounts.UserEmail
        |> Authify.Repo.get!(primary_email.id)
        |> Ecto.Changeset.change(%{
          verified_at: nil,
          verification_token: nil,
          verification_expires_at: nil
        })
        |> Authify.Repo.update()

      conn =
        conn
        |> recycle()
        |> log_in_user(Authify.Repo.preload(user, :emails))
        |> post(~p"/#{user.organization.slug}/profile/resend-verification")

      assert redirected_to(conn) == ~p"/#{user.organization.slug}/profile"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "Verification email sent!"

      events =
        AuditLog.list_events(
          organization_id: user.organization_id,
          event_type: "email_verification_resent"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "success"
      assert event.metadata["source"] == "web"
      assert event.metadata["user_id"] == user.id
      assert event.metadata["email"] == User.get_primary_email_value(user)
      assert event.metadata["organization_slug"] == user.organization.slug
    end

    test "already verified logs failure", %{conn: conn, user: user} do
      # Ensure user is verified by verifying their primary email
      user = Authify.Repo.preload(user, :emails)
      primary_email = Authify.Accounts.User.get_primary_email(user)

      {:ok, _verified_email} =
        Authify.Accounts.UserEmail
        |> Authify.Repo.get!(primary_email.id)
        |> Authify.Accounts.UserEmail.verify_changeset()
        |> Authify.Repo.update()

      verified_user = Authify.Repo.preload(user, :emails, force: true)

      conn =
        conn
        |> recycle()
        |> log_in_user(verified_user)
        |> post(~p"/#{user.organization.slug}/profile/resend-verification")

      assert redirected_to(conn) == ~p"/#{user.organization.slug}/profile"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "already verified"

      events =
        AuditLog.list_events(
          organization_id: user.organization_id,
          event_type: "email_verification_resent"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "failure"
      assert event.metadata["source"] == "web"
      assert event.metadata["reason"] == "already_verified"
      assert event.metadata["user_id"] == verified_user.id
      assert event.metadata["email"] == User.get_primary_email_value(verified_user)
    end

    # Note: Testing email send failure is challenging with the test adapter since it always succeeds.
    # The audit logging code for email failure exists in ProfileController at lines 160-170
    # and includes proper error logging with reason "email_send_failed" and email_error metadata.
  end

  describe "personal_access_tokens" do
    test "renders personal access tokens page", %{conn: conn, user: user} do
      org = user.organization
      conn = get(conn, ~p"/#{org.slug}/profile/personal-access-tokens")
      response = html_response(conn, 200)
      assert response =~ "Personal Access Tokens"
      assert response =~ "Create New Token"
      assert response =~ "No personal access tokens"
    end

    test "creates personal access token successfully", %{conn: conn, user: user} do
      organization = user.organization

      pat_params = %{
        "name" => "Test API Token",
        "description" => "Token for testing",
        "scopes" => ["profile:read", "profile:write"]
      }

      conn =
        post(conn, ~p"/#{organization.slug}/profile/personal-access-tokens",
          personal_access_token: pat_params
        )

      assert redirected_to(conn) == ~p"/#{organization.slug}/profile/personal-access-tokens"

      follow_conn =
        conn |> recycle() |> get(~p"/#{organization.slug}/profile/personal-access-tokens")

      response = html_response(follow_conn, 200)

      # Test that the token appears in the list (functionality works)
      assert response =~ "Test API Token"
      assert response =~ "Token for testing"
      assert response =~ "profile:read, profile:write"

      # Verify token was created in database
      tokens = Accounts.list_personal_access_tokens(user)
      assert length(tokens) == 1

      token = hd(tokens)
      assert token.name == "Test API Token"
      assert token.description == "Token for testing"
      assert PersonalAccessToken.scopes_list(token) == ["profile:read", "profile:write"]
      assert token.user_id == user.id
      assert token.organization_id == organization.id

      events =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "personal_access_token_created"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "success"
      assert event.metadata["source"] == "web"
      assert event.metadata["personal_access_token_id"] == token.id
      assert Enum.sort(event.metadata["scopes"]) == ["profile:read", "profile:write"]
    end

    test "shows validation errors for invalid token", %{conn: conn, user: user} do
      org = user.organization

      pat_params = %{
        # Empty name should fail validation
        "name" => "",
        "scopes" => []
      }

      conn =
        post(conn, ~p"/#{org.slug}/profile/personal-access-tokens",
          personal_access_token: pat_params
        )

      response = html_response(conn, 200)
      assert response =~ "can&#39;t be blank"

      events =
        AuditLog.list_events(
          organization_id: org.id,
          event_type: "personal_access_token_created"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "failure"
      assert event.metadata["source"] == "web"
      assert Enum.any?(event.metadata["errors"], &String.contains?(&1, "name"))
    end

    test "deletes personal access token", %{conn: conn, user: user} do
      organization = user.organization

      {:ok, token} =
        Accounts.create_personal_access_token(user, organization, %{
          "name" => "Token to Delete",
          "scopes" => "profile:read"
        })

      conn = delete(conn, ~p"/#{organization.slug}/profile/personal-access-tokens/#{token.id}")

      assert redirected_to(conn) == ~p"/#{organization.slug}/profile/personal-access-tokens"

      follow_conn =
        conn |> recycle() |> get(~p"/#{organization.slug}/profile/personal-access-tokens")

      response = html_response(follow_conn, 200)

      # Test that the page shows no tokens (functionality works)
      assert response =~ "No personal access tokens"

      # Verify token was deleted from database
      tokens = Accounts.list_personal_access_tokens(user)
      assert Enum.empty?(tokens)

      events =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "personal_access_token_deleted"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "success"
      assert event.metadata["source"] == "web"
      assert event.metadata["personal_access_token_id"] == token.id
    end

    test "cannot delete another user's token", %{conn: conn, user: user} do
      org = user.organization
      other_user = user_fixture()
      organization = other_user.organization

      {:ok, other_token} =
        Accounts.create_personal_access_token(other_user, organization, %{
          "name" => "Other User Token",
          "scopes" => "profile:read"
        })

      # This should raise an error since we try to get a token that doesn't belong to current user
      assert_raise Ecto.NoResultsError, fn ->
        delete(conn, ~p"/#{org.slug}/profile/personal-access-tokens/#{other_token.id}")
      end
    end

    test "creates personal access token with invitation scopes", %{conn: conn, user: user} do
      organization = user.organization

      pat_params = %{
        "name" => "Invitations API Token",
        "description" => "Token for managing invitations via API",
        "scopes" => ["invitations:read", "invitations:write", "users:read"]
      }

      conn =
        post(conn, ~p"/#{organization.slug}/profile/personal-access-tokens",
          personal_access_token: pat_params
        )

      assert redirected_to(conn) == ~p"/#{organization.slug}/profile/personal-access-tokens"

      follow_conn =
        conn |> recycle() |> get(~p"/#{organization.slug}/profile/personal-access-tokens")

      response = html_response(follow_conn, 200)

      # Test that the token appears in the list with correct scopes
      assert response =~ "Invitations API Token"
      assert response =~ "Token for managing invitations via API"
      assert response =~ "invitations:read, invitations:write, users:read"

      # Verify token was created in database with correct scopes
      tokens = Accounts.list_personal_access_tokens(user)
      token = Enum.find(tokens, &(&1.name == "Invitations API Token"))

      assert token.name == "Invitations API Token"
      assert token.description == "Token for managing invitations via API"

      assert PersonalAccessToken.scopes_list(token) == [
               "invitations:read",
               "invitations:write",
               "users:read"
             ]

      assert token.user_id == user.id
      assert token.organization_id == organization.id

      # Verify token has the expected scopes
      scopes_list = PersonalAccessToken.scopes_list(token)
      assert "invitations:read" in scopes_list
      assert "invitations:write" in scopes_list
      assert "users:read" in scopes_list

      events =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "personal_access_token_created"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "success"
      assert event.metadata["source"] == "web"

      assert Enum.sort(event.metadata["scopes"]) ==
               ["invitations:read", "invitations:write", "users:read"]
    end
  end

  describe "email management" do
    test "renders emails page with existing emails", %{conn: conn, user: user} do
      org = user.organization
      conn = get(conn, ~p"/#{org.slug}/profile/emails")
      response = html_response(conn, 200)

      assert response =~ "Email Addresses"
      assert response =~ "Add Email Address"
      # User should have their primary email displayed
      assert response =~ User.get_primary_email_value(user)
    end

    test "adds a new email address", %{conn: conn, user: user} do
      org = user.organization
      new_email = "newemail-#{System.unique_integer([:positive])}@example.com"

      conn =
        post(conn, ~p"/#{org.slug}/profile/emails", %{
          "user_email" => %{"value" => new_email, "type" => "work"}
        })

      assert redirected_to(conn) == ~p"/#{org.slug}/profile/emails"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "Email address added"

      # Verify email was added
      updated_user = Authify.Repo.preload(user, :emails, force: true)
      assert Enum.any?(updated_user.emails, &(&1.value == new_email))

      # Verify audit log
      events = AuditLog.list_events(organization_id: org.id, event_type: "email_added")
      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "success"
      assert event.metadata["email_value"] == new_email
    end

    test "shows error when adding duplicate email", %{conn: conn, user: user} do
      org = user.organization
      existing_email = User.get_primary_email_value(user)

      conn =
        post(conn, ~p"/#{org.slug}/profile/emails", %{
          "user_email" => %{"value" => existing_email, "type" => "work"}
        })

      response = html_response(conn, 200)
      assert response =~ "already in use"
    end

    test "shows error when adding invalid email format", %{conn: conn, user: user} do
      org = user.organization

      conn =
        post(conn, ~p"/#{org.slug}/profile/emails", %{
          "user_email" => %{"value" => "not-an-email", "type" => "work"}
        })

      response = html_response(conn, 200)
      assert response =~ "invalid format"
    end

    test "deletes non-primary email", %{conn: conn, user: user} do
      org = user.organization

      # Add a secondary email first
      {:ok, secondary_email} =
        Accounts.add_email_to_user(user, %{"value" => "secondary@example.com", "type" => "home"})

      conn = delete(conn, ~p"/#{org.slug}/profile/emails/#{secondary_email.id}")

      assert redirected_to(conn) == ~p"/#{org.slug}/profile/emails"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "Email address removed"

      # Verify email was deleted
      updated_user = Authify.Repo.preload(user, :emails, force: true)
      refute Enum.any?(updated_user.emails, &(&1.id == secondary_email.id))

      # Verify audit log
      events = AuditLog.list_events(organization_id: org.id, event_type: "email_deleted")
      assert length(events) == 1
    end

    test "cannot delete primary email", %{conn: conn, user: user} do
      org = user.organization
      user = Authify.Repo.preload(user, :emails)
      primary_email = User.get_primary_email(user)

      conn = delete(conn, ~p"/#{org.slug}/profile/emails/#{primary_email.id}")

      assert redirected_to(conn) == ~p"/#{org.slug}/profile/emails"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Cannot delete your primary email"

      # Verify email was NOT deleted
      updated_user = Authify.Repo.preload(user, :emails, force: true)
      assert Enum.any?(updated_user.emails, &(&1.id == primary_email.id))
    end

    test "sets verified email as primary", %{conn: conn, user: user} do
      org = user.organization

      # Add and verify a secondary email
      {:ok, secondary_email} =
        Accounts.add_email_to_user(user, %{
          "value" => "secondary-primary@example.com",
          "type" => "home"
        })

      # Verify the secondary email
      {:ok, verified_email} =
        secondary_email
        |> UserEmail.verify_changeset()
        |> Authify.Repo.update()

      conn = post(conn, ~p"/#{org.slug}/profile/emails/#{verified_email.id}/set-primary")

      assert redirected_to(conn) == ~p"/#{org.slug}/profile/emails"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "Primary email updated"

      # Verify the change
      updated_user = Authify.Repo.preload(user, :emails, force: true)
      new_primary = User.get_primary_email(updated_user)
      assert new_primary.id == verified_email.id

      # Verify audit log
      events = AuditLog.list_events(organization_id: org.id, event_type: "primary_email_changed")
      assert length(events) == 1
    end

    test "cannot set unverified email as primary", %{conn: conn, user: user} do
      org = user.organization

      # Add a secondary email (unverified)
      {:ok, unverified_email} =
        Accounts.add_email_to_user(user, %{"value" => "unverified@example.com", "type" => "home"})

      conn = post(conn, ~p"/#{org.slug}/profile/emails/#{unverified_email.id}/set-primary")

      assert redirected_to(conn) == ~p"/#{org.slug}/profile/emails"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "verified"

      # Verify the primary email was NOT changed
      updated_user = Authify.Repo.preload(user, :emails, force: true)
      new_primary = User.get_primary_email(updated_user)
      refute new_primary.id == unverified_email.id
    end

    test "resends verification email for unverified address", %{conn: conn, user: user} do
      org = user.organization

      # Add an unverified email
      {:ok, unverified_email} =
        Accounts.add_email_to_user(user, %{"value" => "verify-me@example.com", "type" => "work"})

      conn =
        post(conn, ~p"/#{org.slug}/profile/emails/#{unverified_email.id}/resend-verification")

      assert redirected_to(conn) == ~p"/#{org.slug}/profile/emails"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "Verification email sent"

      # Verify audit log
      events =
        AuditLog.list_events(organization_id: org.id, event_type: "email_verification_resent")

      refute Enum.empty?(events)
    end

    test "shows message when resending verification for already verified email", %{
      conn: conn,
      user: user
    } do
      org = user.organization

      # Add and verify a secondary email
      {:ok, email} =
        Accounts.add_email_to_user(user, %{
          "value" => "already-verified@example.com",
          "type" => "work"
        })

      {:ok, verified_email} =
        email
        |> UserEmail.verify_changeset()
        |> Authify.Repo.update()

      conn = post(conn, ~p"/#{org.slug}/profile/emails/#{verified_email.id}/resend-verification")

      assert redirected_to(conn) == ~p"/#{org.slug}/profile/emails"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "already verified"
    end

    test "shows error when email not found", %{conn: conn, user: user} do
      org = user.organization

      conn = delete(conn, ~p"/#{org.slug}/profile/emails/999999")

      assert redirected_to(conn) == ~p"/#{org.slug}/profile/emails"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "not found"
    end
  end
end
