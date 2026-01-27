defmodule AuthifyWeb.InvitationControllerTest do
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures

  alias Authify.Accounts
  alias Authify.AuditLog
  alias Authify.Guardian

  describe "index" do
    setup :create_user_and_login

    @tag :capture_log
    test "lists all invitations for organization", %{conn: conn, organization: org, user: admin} do
      invitation = invitation_for_organization_fixture(org, admin)
      conn = get(conn, ~p"/#{org.slug}/invitations")

      assert html_response(conn, 200) =~ "Invitations"
      assert html_response(conn, 200) =~ invitation.email
    end

    test "shows empty state when no invitations", %{conn: conn, organization: org} do
      conn = get(conn, ~p"/#{org.slug}/invitations")

      assert html_response(conn, 200) =~ "No invitations found"
      assert html_response(conn, 200) =~ "Invite your first user"
    end
  end

  describe "new invitation" do
    setup :create_user_and_login

    test "renders form", %{conn: conn, organization: org} do
      conn = get(conn, ~p"/#{org.slug}/invitations/new")
      assert html_response(conn, 200) =~ "Invite User"
      assert html_response(conn, 200) =~ "Send Invitation"
    end
  end

  describe "create invitation" do
    setup :create_user_and_login

    @tag :capture_log
    test "redirects to index when data is valid", %{conn: conn, organization: org} do
      invitation_params = %{
        "email" => unique_user_email(),
        "role" => "user"
      }

      conn = post(conn, ~p"/#{org.slug}/invitations", invitation: invitation_params)

      assert redirected_to(conn) == ~p"/#{org.slug}/invitations"

      conn = get(conn, ~p"/#{org.slug}/invitations")
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "Invitation sent successfully"

      events =
        AuditLog.list_events(
          organization_id: org.id,
          event_type: "user_invited"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "success"
      assert event.metadata["invited_email"] == invitation_params["email"]
      assert event.metadata["invited_role"] == invitation_params["role"]
      assert event.metadata["source"] == "web"
    end

    test "renders errors when data is invalid", %{conn: conn, organization: org} do
      invalid_params = %{
        "email" => "invalid-email",
        "role" => "invalid_role"
      }

      conn = post(conn, ~p"/#{org.slug}/invitations", invitation: invalid_params)

      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~
               "There was an error sending the invitation"

      events =
        AuditLog.list_events(
          organization_id: org.id,
          event_type: "user_invited"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "failure"
      assert event.metadata["source"] == "web"
      assert Enum.any?(event.metadata["errors"], &String.contains?(&1, "email"))
    end

    @tag :capture_log
    test "renders errors when email already invited", %{
      conn: conn,
      organization: org,
      user: admin
    } do
      # Create existing invitation
      existing_email = unique_user_email()

      _existing_invitation =
        invitation_for_organization_fixture(org, admin, %{"email" => existing_email})

      # Try to invite same email again
      invitation_params = %{
        "email" => existing_email,
        "role" => "user"
      }

      conn = post(conn, ~p"/#{org.slug}/invitations", invitation: invitation_params)

      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~
               "There was an error sending the invitation"
    end
  end

  describe "show invitation" do
    setup :create_user_and_login

    @tag :capture_log
    test "displays invitation details", %{conn: conn, organization: org, user: admin} do
      invitation = invitation_for_organization_fixture(org, admin)
      conn = get(conn, ~p"/#{org.slug}/invitations/#{invitation.id}")

      assert html_response(conn, 200) =~ "Invitation Details"
      assert html_response(conn, 200) =~ invitation.email
    end

    @tag :capture_log
    test "redirects when invitation belongs to different organization", %{
      conn: conn,
      organization: org
    } do
      other_org = organization_fixture()
      other_admin = admin_user_fixture(other_org)
      other_invitation = invitation_for_organization_fixture(other_org, other_admin)

      conn = get(conn, ~p"/#{org.slug}/invitations/#{other_invitation.id}")

      assert redirected_to(conn) == ~p"/#{org.slug}/invitations"

      conn = get(conn, ~p"/#{org.slug}/invitations")
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Invitation not found"
    end
  end

  describe "delete invitation" do
    setup :create_user_and_login

    @tag :capture_log
    test "deletes chosen invitation", %{conn: conn, organization: org, user: admin} do
      invitation = invitation_for_organization_fixture(org, admin)
      conn = delete(conn, ~p"/#{org.slug}/invitations/#{invitation.id}")

      assert redirected_to(conn) == ~p"/#{org.slug}/invitations"

      conn = get(conn, ~p"/#{org.slug}/invitations")
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "Invitation cancelled successfully"

      assert_raise Ecto.NoResultsError, fn ->
        Accounts.get_invitation!(invitation.id)
      end

      events =
        AuditLog.list_events(
          organization_id: org.id,
          event_type: "invitation_revoked"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "success"
      assert event.metadata["invitation_id"] == invitation.id
      assert event.metadata["invited_email"] == invitation.email
      assert event.metadata["source"] == "web"
    end

    @tag :capture_log
    test "redirects when invitation belongs to different organization", %{
      conn: conn,
      organization: org
    } do
      other_org = organization_fixture()
      other_admin = admin_user_fixture(other_org)
      other_invitation = invitation_for_organization_fixture(other_org, other_admin)

      conn = delete(conn, ~p"/#{org.slug}/invitations/#{other_invitation.id}")

      assert redirected_to(conn) == ~p"/#{org.slug}/invitations"

      conn = get(conn, ~p"/#{org.slug}/invitations")
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Invitation not found"

      # Invitation should still exist
      assert Accounts.get_invitation!(other_invitation.id)
    end
  end

  describe "accept invitation (public)" do
    @tag :capture_log
    test "renders acceptance form for valid pending invitation", %{conn: conn} do
      organization = organization_fixture()
      admin = admin_user_fixture(organization)
      invitation = invitation_for_organization_fixture(organization, admin)

      conn = get(conn, ~p"/invite/#{invitation.token}")

      assert html_response(conn, 200) =~ "Accept Invitation"
      assert html_response(conn, 200) =~ "You've been invited to join"
      assert html_response(conn, 200) =~ organization.name
      assert html_response(conn, 200) =~ invitation.email
    end

    test "redirects for invalid token", %{conn: conn} do
      conn = get(conn, ~p"/invite/invalid-token")

      assert redirected_to(conn) == ~p"/"

      conn = get(conn, ~p"/")
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Invalid or expired invitation"
    end

    test "redirects for expired invitation", %{conn: conn} do
      organization = organization_fixture()
      admin = admin_user_fixture(organization)

      # Create expired invitation
      expired_attrs = %{
        "email" => unique_user_email(),
        "role" => "user",
        "organization_id" => organization.id,
        "invited_by_id" => admin.id,
        "expires_at" => DateTime.add(DateTime.utc_now(), -1, :day) |> DateTime.truncate(:second)
      }

      {:ok, expired_invitation} = Accounts.create_invitation(expired_attrs)

      conn = get(conn, ~p"/invite/#{expired_invitation.token}")

      assert redirected_to(conn) == ~p"/"

      conn = get(conn, ~p"/")
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "This invitation has expired"
    end

    @tag :capture_log
    test "redirects for already accepted invitation", %{conn: conn} do
      organization = organization_fixture()
      admin = admin_user_fixture(organization)
      invitation = invitation_for_organization_fixture(organization, admin)

      # Accept the invitation first
      user_attrs = %{
        "first_name" => "John",
        "last_name" => "Doe",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      {:ok, _user} = Accounts.accept_invitation(invitation, user_attrs)

      conn = get(conn, ~p"/invite/#{invitation.token}")

      assert redirected_to(conn) == ~p"/"

      conn = get(conn, ~p"/")

      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~
               "This invitation has already been accepted"
    end
  end

  describe "accept_invitation (public)" do
    @tag :capture_log
    test "creates user and redirects on success", %{conn: conn} do
      organization = organization_fixture()
      admin = admin_user_fixture(organization)
      invitation = invitation_for_organization_fixture(organization, admin)

      user_params = %{
        "first_name" => "John",
        "last_name" => "Doe",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      conn = post(conn, ~p"/invite/#{invitation.token}/accept", user: user_params)

      assert redirected_to(conn) == ~p"/login?org_slug=#{organization.slug}"

      # Check user was created
      user = Accounts.get_user_by_email_and_organization(invitation.email, organization.id)
      assert user != nil
      assert user.first_name == "John"
      assert user.last_name == "Doe"

      # Check user has correct role in organization
      user_org = Accounts.get_user_organization(user.id, organization.id)
      assert user_org != nil
      assert user_org.role == invitation.role

      # Check invitation was marked as accepted
      updated_invitation = Accounts.get_invitation!(invitation.id)
      assert updated_invitation.accepted_at != nil

      events =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "user_invitation_accepted"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "success"
      assert event.metadata["invitation_id"] == invitation.id
      assert event.metadata["invited_email"] == invitation.email
      assert event.metadata["user_id"] == user.id
      assert event.metadata["source"] == "web"
    end

    @tag :capture_log
    test "renders errors when user data is invalid", %{conn: conn} do
      organization = organization_fixture()
      admin = admin_user_fixture(organization)
      invitation = invitation_for_organization_fixture(organization, admin)

      invalid_params = %{
        "first_name" => "",
        "password" => "123",
        "password_confirmation" => "456"
      }

      conn = post(conn, ~p"/invite/#{invitation.token}/accept", user: invalid_params)

      assert html_response(conn, 200) =~ "Accept Invitation"
      # Invitation should not be marked as accepted
      unchanged_invitation = Accounts.get_invitation!(invitation.id)
      assert is_nil(unchanged_invitation.accepted_at)
    end

    test "redirects for invalid token", %{conn: conn} do
      user_params = %{
        "first_name" => "John",
        "last_name" => "Doe",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      conn = post(conn, ~p"/invite/invalid-token/accept", user: user_params)

      assert redirected_to(conn) == ~p"/"
    end

    test "redirects for expired invitation", %{conn: conn} do
      organization = organization_fixture()
      admin = admin_user_fixture(organization)

      # Create expired invitation
      expired_attrs = %{
        "email" => unique_user_email(),
        "role" => "user",
        "organization_id" => organization.id,
        "invited_by_id" => admin.id,
        "expires_at" => DateTime.add(DateTime.utc_now(), -1, :day) |> DateTime.truncate(:second)
      }

      {:ok, expired_invitation} = Accounts.create_invitation(expired_attrs)

      user_params = %{
        "first_name" => "John",
        "last_name" => "Doe",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      conn = post(conn, ~p"/invite/#{expired_invitation.token}/accept", user: user_params)

      assert redirected_to(conn) == ~p"/"
    end
  end

  describe "authentication requirements" do
    test "requires authentication for invitation management routes", %{conn: conn} do
      organization = organization_fixture()

      # Test index
      conn = get(conn, ~p"/#{organization.slug}/invitations")
      assert redirected_to(conn) == ~p"/login"

      # Test new
      conn = get(conn, ~p"/#{organization.slug}/invitations/new")
      assert redirected_to(conn) == ~p"/login"

      # Test create
      conn = post(conn, ~p"/#{organization.slug}/invitations", invitation: %{})
      assert redirected_to(conn) == ~p"/login"
    end

    @tag :capture_log
    test "public invitation acceptance routes do not require authentication", %{conn: conn} do
      organization = organization_fixture()
      admin = admin_user_fixture(organization)
      invitation = invitation_for_organization_fixture(organization, admin)

      # Should not redirect to login
      conn = get(conn, ~p"/invite/#{invitation.token}")
      assert html_response(conn, 200) =~ "Accept Invitation"
    end
  end

  defp create_user_and_login(%{conn: conn}) do
    organization = organization_fixture()
    user = admin_user_fixture(organization)

    # Use Guardian to properly sign in the user and let middleware handle organization assignment
    conn =
      conn
      |> Plug.Test.init_test_session(%{})
      |> Guardian.Plug.sign_in(user)

    %{conn: conn, organization: organization, user: user}
  end
end
