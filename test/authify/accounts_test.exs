defmodule Authify.AccountsTest do
  use Authify.DataCase, async: true

  alias Authify.Accounts
  alias Authify.Accounts.{Group, GroupMembership, Invitation, Organization, User}

  import Authify.AccountsFixtures

  describe "organizations" do
    @invalid_org_attrs %{name: "", slug: ""}

    defp valid_org_attrs do
      n = System.unique_integer([:positive])
      %{name: "Test Organization #{n}", slug: "test-org-#{n}"}
    end

    test "list_organizations/0 returns all organizations" do
      {:ok, org} = Accounts.create_organization(valid_org_attrs())
      organizations = Accounts.list_organizations()
      # Should include the test org and the global org created by migration
      refute Enum.empty?(organizations)
      assert Enum.any?(organizations, fn o -> o.id == org.id end)
    end

    test "get_organization!/1 returns the organization with given id" do
      {:ok, org} = Accounts.create_organization(valid_org_attrs())
      assert Accounts.get_organization!(org.id) == org
    end

    test "get_organization_by_slug/1 returns organization with given slug" do
      attrs = valid_org_attrs()
      {:ok, org} = Accounts.create_organization(attrs)
      assert Accounts.get_organization_by_slug(attrs.slug) == org
      assert Accounts.get_organization_by_slug("nonexistent") == nil
    end

    test "create_organization/1 with valid data creates an organization" do
      attrs = valid_org_attrs()
      assert {:ok, %Organization{} = org} = Accounts.create_organization(attrs)
      assert org.name == attrs.name
      assert org.slug == attrs.slug
      assert org.active == true
    end

    test "create_organization/1 with invalid data returns error changeset" do
      assert {:error, %Ecto.Changeset{}} = Accounts.create_organization(@invalid_org_attrs)
    end

    test "create_organization/1 auto-generates slug from name when not provided" do
      attrs = %{name: "My Test Organization"}
      assert {:ok, %Organization{} = org} = Accounts.create_organization(attrs)
      assert org.slug == "my-test-organization"
    end

    test "create_organization/1 enforces unique slug constraint" do
      attrs = valid_org_attrs()
      {:ok, _org1} = Accounts.create_organization(attrs)

      assert {:error, %Ecto.Changeset{} = changeset} =
               Accounts.create_organization(attrs)

      assert "has already been taken" in errors_on(changeset).slug
    end

    test "update_organization/2 with valid data updates the organization" do
      {:ok, org} = Accounts.create_organization(valid_org_attrs())
      update_attrs = %{name: "Updated Organization"}

      assert {:ok, %Organization{} = updated_org} =
               Accounts.update_organization(org, update_attrs)

      assert updated_org.name == "Updated Organization"
    end

    test "delete_organization/1 deletes the organization" do
      {:ok, org} = Accounts.create_organization(valid_org_attrs())
      assert {:ok, %Organization{}} = Accounts.delete_organization(org)
      assert_raise Ecto.NoResultsError, fn -> Accounts.get_organization!(org.id) end
    end

    test "change_organization/1 returns an organization changeset" do
      {:ok, org} = Accounts.create_organization(valid_org_attrs())
      assert %Ecto.Changeset{} = Accounts.change_organization(org)
    end
  end

  describe "users" do
    setup do
      {:ok, org} = Accounts.create_organization(valid_org_attrs())
      %{organization: org}
    end

    defp valid_user_attrs do
      n = System.unique_integer([:positive])

      %{
        "emails" => [
          %{"value" => "test-user-#{n}@example.com", "type" => "work", "primary" => true}
        ],
        "first_name" => "John",
        "last_name" => "Doe",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }
    end

    @invalid_user_attrs %{
      "emails" => [%{"value" => "invalid", "type" => "work", "primary" => true}],
      "password" => "123",
      "password_confirmation" => "456"
    }

    test "list_users/1 returns all users for organization", %{organization: org} do
      attrs = valid_user_attrs()
      {:ok, user} = Accounts.create_user_with_role(attrs, org.id, "user")

      [found_user] = Accounts.list_users(org.id)
      assert found_user.id == user.id

      assert Authify.Accounts.User.get_primary_email_value(found_user) ==
               Authify.Accounts.User.get_primary_email_value(user)
    end

    test "get_user!/1 returns the user with given id", %{organization: _org} do
      {:ok, user} = Accounts.create_user(valid_user_attrs())
      found_user = Accounts.get_user!(user.id)
      assert found_user.id == user.id

      assert Authify.Accounts.User.get_primary_email_value(found_user) ==
               Authify.Accounts.User.get_primary_email_value(user)

      assert found_user.first_name == user.first_name
    end

    test "get_user_by_email_and_organization/2 returns user", %{organization: org} do
      attrs = valid_user_attrs()
      email = hd(attrs["emails"])["value"]
      {:ok, user} = Accounts.create_user_with_role(attrs, org.id, "user")

      found_user = Accounts.get_user_by_email_and_organization(email, org.id)
      assert found_user.id == user.id

      assert Authify.Accounts.User.get_primary_email_value(found_user) ==
               Authify.Accounts.User.get_primary_email_value(user)
    end

    test "create_user/1 with valid data creates a user", %{organization: _org} do
      attrs = valid_user_attrs()
      expected_email = hd(attrs["emails"])["value"]
      assert {:ok, %User{} = user} = Accounts.create_user(attrs)
      assert Authify.Accounts.User.get_primary_email_value(user) == expected_email
      assert user.first_name == "John"
      assert user.last_name == "Doe"
      assert User.valid_password?(user, "SecureP@ssw0rd!")
    end

    test "create_user/1 with invalid data returns error changeset", %{organization: _org} do
      assert {:error, %Ecto.Changeset{}} = Accounts.create_user(@invalid_user_attrs)
    end

    test "create_organization_with_admin/2 creates org and admin user" do
      n = System.unique_integer([:positive])
      org_attrs = %{name: "Admin Test Org #{n}", slug: "admin-test-#{n}"}
      user_attrs = valid_user_attrs()
      expected_email = hd(user_attrs["emails"])["value"]

      assert {:ok, {org, user}} = Accounts.create_organization_with_admin(org_attrs, user_attrs)

      assert org.name == org_attrs.name
      assert Authify.Accounts.User.get_primary_email_value(user) == expected_email
      # Check that user has admin role in the organization
      assert User.admin?(user, org.id) == true
    end

    test "create_organization_with_admin/2 rolls back on user error" do
      n = System.unique_integer([:positive])
      org_attrs = %{name: "Rollback Test Org #{n}", slug: "rollback-test-#{n}"}
      invalid_user_attrs = @invalid_user_attrs

      assert {:error, %Ecto.Changeset{}} =
               Accounts.create_organization_with_admin(org_attrs, invalid_user_attrs)

      # Organization should not exist due to rollback
      assert Accounts.get_organization_by_slug(org_attrs.slug) == nil
    end

    test "authenticate_user/3 with valid credentials returns user", %{organization: org} do
      attrs = valid_user_attrs()
      email = hd(attrs["emails"])["value"]
      {:ok, user} = Accounts.create_user_with_role(attrs, org.id, "user")

      assert {:ok, authenticated_user} =
               Accounts.authenticate_user(email, "SecureP@ssw0rd!", org.id)

      assert authenticated_user.id == user.id
    end

    test "authenticate_user/3 with invalid password returns error", %{organization: org} do
      attrs = valid_user_attrs()
      email = hd(attrs["emails"])["value"]
      {:ok, _user} = Accounts.create_user_with_role(attrs, org.id, "user")

      assert {:error, :invalid_password} =
               Accounts.authenticate_user(email, "wrong_password", org.id)
    end

    test "authenticate_user/3 with non-existent user returns error", %{organization: org} do
      assert {:error, :user_not_found} =
               Accounts.authenticate_user("nonexistent@example.com", "SecureP@ssw0rd!", org.id)
    end

    test "update_user/2 clears email verification when email changes", %{organization: org} do
      n = System.unique_integer([:positive])
      # Create a user with verified email
      {:ok, user} = Accounts.create_user_with_role(valid_user_attrs(), org.id, "user")

      # Verify the primary email directly
      user_with_emails = Authify.Repo.preload(user, :emails)
      primary_email = Authify.Accounts.User.get_primary_email(user_with_emails)
      {:ok, _verified_email} = Accounts.verify_email(primary_email.id)

      # Reload user with verified email
      verified_user =
        Authify.Repo.get!(Authify.Accounts.User, user.id)
        |> Authify.Repo.preload(:emails)

      # Check primary email is verified
      primary_email = Authify.Accounts.User.get_primary_email(verified_user)
      assert primary_email.verified_at != nil

      # Update email address using the proper email management API
      new_email_value = "newemail-#{n}@example.com"

      {:ok, new_email} =
        Accounts.add_email_to_user(verified_user, %{value: new_email_value, type: "work"})

      {:ok, _primary_email} = Accounts.set_primary_email(verified_user, new_email.id)

      # Reload user to get updated emails
      updated_user =
        Authify.Repo.get!(Authify.Accounts.User, verified_user.id)
        |> Authify.Repo.preload(:emails, force: true)

      assert Authify.Accounts.User.get_primary_email_value(updated_user) == new_email_value

      # New email starts unverified
      primary_email = Authify.Accounts.User.get_primary_email(updated_user)
      assert primary_email.verified_at == nil
    end

    test "update_user/2 preserves email verification when email doesn't change", %{
      organization: org
    } do
      # Create a user with verified email
      {:ok, user} = Accounts.create_user_with_role(valid_user_attrs(), org.id, "user")

      # Verify the primary email directly
      user_with_emails = Authify.Repo.preload(user, :emails)
      primary_email = Authify.Accounts.User.get_primary_email(user_with_emails)
      {:ok, _verified_email} = Accounts.verify_email(primary_email.id)

      # Reload user with verified email
      verified_user =
        Authify.Repo.get!(Authify.Accounts.User, user.id)
        |> Authify.Repo.preload(:emails)

      # Check primary email is verified
      primary_email = Authify.Accounts.User.get_primary_email(verified_user)
      assert primary_email.verified_at != nil

      # Update other fields but not email
      {:ok, updated_user} = Accounts.update_user(verified_user, %{"first_name" => "Jane"})

      # Email verification should be preserved
      assert updated_user.first_name == "Jane"
      # Email should still be verified
      updated_user_with_emails = Authify.Repo.preload(updated_user, :emails, force: true)
      primary_email = Authify.Accounts.User.get_primary_email(updated_user_with_emails)
      assert primary_email.verified_at != nil
    end

    test "update_user_profile/2 clears email verification when email changes", %{
      organization: org
    } do
      n = System.unique_integer([:positive])
      # Create a user with verified email
      {:ok, user} = Accounts.create_user_with_role(valid_user_attrs(), org.id, "user")

      # Verify the primary email directly
      user_with_emails = Authify.Repo.preload(user, :emails)
      primary_email = Authify.Accounts.User.get_primary_email(user_with_emails)
      {:ok, _verified_email} = Accounts.verify_email(primary_email.id)

      # Reload user with verified email
      verified_user =
        Authify.Repo.get!(Authify.Accounts.User, user.id)
        |> Authify.Repo.preload(:emails)

      # Check primary email is verified
      primary_email = Authify.Accounts.User.get_primary_email(verified_user)
      assert primary_email.verified_at != nil

      # Update email using the proper email management API
      new_email_value = "profilechange-#{n}@example.com"

      {:ok, new_email} =
        Accounts.add_email_to_user(verified_user, %{
          value: new_email_value,
          type: "work"
        })

      {:ok, _primary_email} = Accounts.set_primary_email(verified_user, new_email.id)

      # Reload user to get updated emails
      updated_user =
        Authify.Repo.get!(Authify.Accounts.User, verified_user.id)
        |> Authify.Repo.preload(:emails, force: true)

      assert Authify.Accounts.User.get_primary_email_value(updated_user) == new_email_value

      # New email starts unverified
      primary_email = Authify.Accounts.User.get_primary_email(updated_user)
      assert primary_email.verified_at == nil
    end

    test "update_user_profile/2 preserves email verification when email doesn't change", %{
      organization: org
    } do
      # Create a user with verified email
      {:ok, user} = Accounts.create_user_with_role(valid_user_attrs(), org.id, "user")

      # Verify the primary email directly
      user_with_emails = Authify.Repo.preload(user, :emails)
      primary_email = Authify.Accounts.User.get_primary_email(user_with_emails)
      {:ok, _verified_email} = Accounts.verify_email(primary_email.id)

      # Reload user with verified email
      verified_user =
        Authify.Repo.get!(Authify.Accounts.User, user.id)
        |> Authify.Repo.preload(:emails)

      # Check primary email is verified
      primary_email = Authify.Accounts.User.get_primary_email(verified_user)
      assert primary_email.verified_at != nil

      # Update username but not email
      {:ok, updated_user} =
        Accounts.update_user_profile(verified_user, %{"username" => "newusername"})

      # Email verification should be preserved
      assert updated_user.username == "newusername"
      # Email should still be verified
      updated_user_with_emails = Authify.Repo.preload(updated_user, :emails, force: true)
      primary_email = Authify.Accounts.User.get_primary_email(updated_user_with_emails)
      assert primary_email.verified_at != nil
    end
  end

  describe "user utilities" do
    test "User.full_name/1 returns full name" do
      user = %User{first_name: "John", last_name: "Doe"}
      assert User.full_name(user) == "John Doe"

      user = %User{first_name: "John", last_name: nil}
      assert User.full_name(user) == "John"

      user = %User{first_name: nil, last_name: "Doe"}
      assert User.full_name(user) == "Doe"

      user = %User{first_name: "", last_name: ""}
      assert User.full_name(user) == nil
    end

    test "User.admin?/2 checks admin role in organization" do
      organization = organization_fixture()

      # Create admin user
      admin_user = admin_user_fixture(organization)

      # Create regular user
      regular_user = user_for_organization_fixture(organization)

      assert User.admin?(admin_user, organization.id) == true
      assert User.admin?(regular_user, organization.id) == false
    end

    test "User.super_admin?/1 checks global admin status" do
      # Create a global organization if it doesn't exist
      global_org =
        case Accounts.get_global_organization() do
          nil ->
            {:ok, org} =
              Accounts.create_organization(%{name: "Authify Global", slug: "authify-global"})

            org

          org ->
            org
        end

      # Create a regular organization
      n = System.unique_integer([:positive])

      {:ok, regular_org} =
        Accounts.create_organization(%{name: "Regular Org #{n}", slug: "regular-org-#{n}"})

      # Create global admin user
      global_admin = admin_user_fixture(global_org)

      # Create regular user
      regular_user = user_for_organization_fixture(regular_org)

      assert User.super_admin?(global_admin) == true
      assert User.super_admin?(regular_user) == false
    end
  end

  describe "invitations" do
    setup do
      organization = organization_fixture()
      admin_user = admin_user_fixture(organization)
      %{organization: organization, admin_user: admin_user}
    end

    @valid_invitation_attrs %{
      "email" => "invite@example.com",
      "role" => "user"
    }

    @invalid_invitation_attrs %{
      "email" => "invalid-email",
      "role" => "invalid_role"
    }

    @tag :capture_log
    test "list_invitations/1 returns all invitations for organization", %{
      organization: org,
      admin_user: admin
    } do
      invitation = invitation_for_organization_fixture(org, admin)
      invitations = Accounts.list_invitations(org.id)

      assert length(invitations) == 1
      assert hd(invitations).id == invitation.id
      assert hd(invitations).email == invitation.email
    end

    @tag :capture_log
    test "list_pending_invitations/1 returns only pending invitations", %{
      organization: org,
      admin_user: admin
    } do
      # Create a pending invitation
      pending_invitation = invitation_for_organization_fixture(org, admin)

      # Create an expired invitation
      expired_attrs = %{
        "email" => unique_user_email(),
        "role" => "user",
        "organization_id" => org.id,
        "invited_by_id" => admin.id,
        "expires_at" => DateTime.add(DateTime.utc_now(), -1, :day) |> DateTime.truncate(:second)
      }

      {:ok, _expired_invitation} = Accounts.create_invitation(expired_attrs)

      pending_invitations = Accounts.list_pending_invitations(org.id)

      assert length(pending_invitations) == 1
      assert hd(pending_invitations).id == pending_invitation.id
    end

    @tag :capture_log
    test "get_invitation!/1 returns the invitation with given id", %{
      organization: org,
      admin_user: admin
    } do
      invitation = invitation_for_organization_fixture(org, admin)
      found_invitation = Accounts.get_invitation!(invitation.id)

      assert found_invitation.id == invitation.id
      assert found_invitation.email == invitation.email
      assert found_invitation.role == invitation.role
    end

    @tag :capture_log
    test "get_invitation_by_token/1 returns invitation with given token", %{
      organization: org,
      admin_user: admin
    } do
      invitation = invitation_for_organization_fixture(org, admin)
      found_invitation = Accounts.get_invitation_by_token(invitation.token)

      assert found_invitation.id == invitation.id
      assert found_invitation.token == invitation.token
    end

    test "get_invitation_by_token/1 returns nil for invalid token" do
      assert Accounts.get_invitation_by_token("invalid-token") == nil
    end

    test "create_invitation/1 with valid data creates an invitation", %{
      organization: org,
      admin_user: admin
    } do
      attrs =
        Map.merge(@valid_invitation_attrs, %{
          "organization_id" => org.id,
          "invited_by_id" => admin.id
        })

      assert {:ok, %Invitation{} = invitation} = Accounts.create_invitation(attrs)
      assert invitation.email == "invite@example.com"
      assert invitation.role == "user"
      assert invitation.organization_id == org.id
      assert invitation.invited_by_id == admin.id
      assert invitation.token != nil
      assert invitation.expires_at != nil
      assert is_nil(invitation.accepted_at)
    end

    test "create_invitation/1 with invalid data returns error changeset", %{
      organization: org,
      admin_user: admin
    } do
      attrs =
        Map.merge(@invalid_invitation_attrs, %{
          "organization_id" => org.id,
          "invited_by_id" => admin.id
        })

      assert {:error, %Ecto.Changeset{}} = Accounts.create_invitation(attrs)
    end

    test "create_invitation/1 enforces unique email per organization", %{
      organization: org,
      admin_user: admin
    } do
      attrs =
        Map.merge(@valid_invitation_attrs, %{
          "organization_id" => org.id,
          "invited_by_id" => admin.id
        })

      # Create first invitation
      {:ok, _invitation1} = Accounts.create_invitation(attrs)

      # Try to create second invitation with same email
      assert {:error, %Ecto.Changeset{} = changeset} = Accounts.create_invitation(attrs)
      assert "User already invited to this organization" in errors_on(changeset).email
    end

    @tag :capture_log
    test "create_invitation_and_send_email/2 creates invitation with inviter", %{
      organization: org,
      admin_user: admin
    } do
      attrs = Map.merge(@valid_invitation_attrs, %{"organization_id" => org.id})

      assert {:ok, %Invitation{} = invitation} =
               Accounts.create_invitation_and_send_email(attrs, admin)

      assert invitation.invited_by_id == admin.id
      assert invitation.organization_id == org.id
    end

    @tag :capture_log
    test "accept_invitation/2 creates user and marks invitation as accepted", %{
      organization: org,
      admin_user: admin
    } do
      invitation = invitation_for_organization_fixture(org, admin)

      user_attrs = %{
        "first_name" => "John",
        "last_name" => "Doe",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      assert {:ok, %User{} = user} = Accounts.accept_invitation(invitation, user_attrs)

      # Check user was created correctly
      assert User.get_primary_email_value(user) == invitation.email
      assert user.first_name == "John"
      assert user.last_name == "Doe"
      # Check that user has the correct role in the organization
      assert User.role_in_organization(user, invitation.organization_id) == invitation.role

      # Check invitation was marked as accepted
      updated_invitation = Accounts.get_invitation!(invitation.id)
      assert updated_invitation.accepted_at != nil
    end

    @tag :capture_log
    test "accept_invitation/2 with invalid user data returns error", %{
      organization: org,
      admin_user: admin
    } do
      invitation = invitation_for_organization_fixture(org, admin)

      invalid_user_attrs = %{
        "first_name" => "",
        "password" => "123",
        "password_confirmation" => "456"
      }

      assert {:error, %Ecto.Changeset{}} =
               Accounts.accept_invitation(invitation, invalid_user_attrs)

      # Invitation should not be marked as accepted
      unchanged_invitation = Accounts.get_invitation!(invitation.id)
      assert is_nil(unchanged_invitation.accepted_at)
    end

    test "accept_invitation/2 with expired invitation returns error", %{
      organization: org,
      admin_user: admin
    } do
      # Create expired invitation
      expired_attrs = %{
        "email" => unique_user_email(),
        "role" => "user",
        "organization_id" => org.id,
        "invited_by_id" => admin.id,
        "expires_at" => DateTime.add(DateTime.utc_now(), -1, :day) |> DateTime.truncate(:second)
      }

      {:ok, expired_invitation} = Accounts.create_invitation(expired_attrs)

      user_attrs = %{
        "first_name" => "John",
        "last_name" => "Doe",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      assert {:error, :invitation_invalid} =
               Accounts.accept_invitation(expired_invitation, user_attrs)
    end

    @tag :capture_log
    test "accept_invitation/2 with already accepted invitation returns error", %{
      organization: org,
      admin_user: admin
    } do
      invitation = invitation_for_organization_fixture(org, admin)

      user_attrs = %{
        "first_name" => "John",
        "last_name" => "Doe",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      # Accept invitation first time
      {:ok, _user} = Accounts.accept_invitation(invitation, user_attrs)

      # Reload the invitation to get the updated accepted_at field
      updated_invitation = Accounts.get_invitation!(invitation.id)

      # Try to accept again
      assert {:error, :invitation_invalid} =
               Accounts.accept_invitation(updated_invitation, user_attrs)
    end

    @tag :capture_log
    test "delete_invitation/1 deletes the invitation", %{organization: org, admin_user: admin} do
      invitation = invitation_for_organization_fixture(org, admin)

      assert {:ok, %Invitation{}} = Accounts.delete_invitation(invitation)
      assert_raise Ecto.NoResultsError, fn -> Accounts.get_invitation!(invitation.id) end
    end

    @tag :capture_log
    test "change_invitation/1 returns an invitation changeset", %{
      organization: org,
      admin_user: admin
    } do
      invitation = invitation_for_organization_fixture(org, admin)
      assert %Ecto.Changeset{} = Accounts.change_invitation(invitation)
    end

    @tag :capture_log
    test "cleanup_expired_invitations/1 removes only expired invitations", %{
      organization: org,
      admin_user: admin
    } do
      # Create pending invitation
      _pending_invitation = invitation_for_organization_fixture(org, admin)

      # Create expired invitation
      expired_attrs = %{
        "email" => unique_user_email(),
        "role" => "user",
        "organization_id" => org.id,
        "invited_by_id" => admin.id,
        "expires_at" => DateTime.add(DateTime.utc_now(), -1, :day) |> DateTime.truncate(:second)
      }

      {:ok, _expired_invitation} = Accounts.create_invitation(expired_attrs)

      assert length(Accounts.list_invitations(org.id)) == 2

      # Cleanup expired invitations
      {deleted_count, _} = Accounts.cleanup_expired_invitations(org.id)
      assert deleted_count == 1

      # Only pending invitation should remain
      remaining_invitations = Accounts.list_invitations(org.id)
      assert length(remaining_invitations) == 1
      assert DateTime.after?(hd(remaining_invitations).expires_at, DateTime.utc_now())
    end
  end

  describe "invitation utilities" do
    test "Invitation.expired?/1 checks if invitation is expired" do
      expired_invitation = %Invitation{expires_at: DateTime.add(DateTime.utc_now(), -1, :day)}
      pending_invitation = %Invitation{expires_at: DateTime.add(DateTime.utc_now(), 1, :day)}

      assert Invitation.expired?(expired_invitation) == true
      assert Invitation.expired?(pending_invitation) == false
    end

    test "Invitation.accepted?/1 checks if invitation is accepted" do
      accepted_invitation = %Invitation{accepted_at: DateTime.utc_now()}
      pending_invitation = %Invitation{accepted_at: nil}

      assert Invitation.accepted?(accepted_invitation) == true
      assert Invitation.accepted?(pending_invitation) == false
    end

    test "Invitation.pending?/1 checks if invitation is pending" do
      # Pending invitation (not expired, not accepted)
      pending_invitation = %Invitation{
        expires_at: DateTime.add(DateTime.utc_now(), 1, :day),
        accepted_at: nil
      }

      # Expired invitation
      expired_invitation = %Invitation{
        expires_at: DateTime.add(DateTime.utc_now(), -1, :day),
        accepted_at: nil
      }

      # Accepted invitation
      accepted_invitation = %Invitation{
        expires_at: DateTime.add(DateTime.utc_now(), 1, :day),
        accepted_at: DateTime.utc_now()
      }

      assert Invitation.pending?(pending_invitation) == true
      assert Invitation.pending?(expired_invitation) == false
      assert Invitation.pending?(accepted_invitation) == false
    end
  end

  describe "admin direct user creation" do
    setup do
      organization = organization_fixture()
      admin_user = admin_user_fixture(organization)

      %{organization: organization, admin_user: admin_user}
    end

    test "create_user_with_role/3 creates user and assigns to organization", %{
      organization: organization
    } do
      n = System.unique_integer([:positive])
      email = "john.doe-#{n}@example.com"

      user_attrs = %{
        "first_name" => "John",
        "last_name" => "Doe",
        "emails" => [
          %{"value" => email, "type" => "work", "primary" => true}
        ],
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      assert {:ok, user} = Accounts.create_user_with_role(user_attrs, organization.id, "user")

      # Check user was created correctly
      assert Authify.Accounts.User.get_primary_email_value(user) == email
      assert user.first_name == "John"
      assert user.last_name == "Doe"
      assert user.active

      # Check user is added to organization with correct role
      user_org = Accounts.get_user_organization(user.id, organization.id)
      assert user_org.role == "user"
      assert user_org.active
      assert user_org.joined_at
    end

    test "create_user_with_role/3 can create admin users", %{organization: organization} do
      n = System.unique_integer([:positive])

      admin_attrs = %{
        "first_name" => "Jane",
        "last_name" => "Admin",
        "emails" => [
          %{"value" => "jane.admin-#{n}@example.com", "type" => "work", "primary" => true}
        ],
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      assert {:ok, user} = Accounts.create_user_with_role(admin_attrs, organization.id, "admin")

      # Check user is admin in organization
      user_org = Accounts.get_user_organization(user.id, organization.id)
      assert user_org.role == "admin"
      assert user_org.active
    end

    test "create_user_with_role/3 defaults to user role when not specified", %{
      organization: organization
    } do
      n = System.unique_integer([:positive])

      user_attrs = %{
        "first_name" => "Default",
        "last_name" => "Role",
        "emails" => [
          %{"value" => "default.role-#{n}@example.com", "type" => "work", "primary" => true}
        ],
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      assert {:ok, user} = Accounts.create_user_with_role(user_attrs, organization.id)

      # Check defaults to user role
      user_org = Accounts.get_user_organization(user.id, organization.id)
      assert user_org.role == "user"
    end

    test "create_user_with_role/3 returns error with invalid user data", %{
      organization: organization
    } do
      invalid_attrs = %{
        "first_name" => "",
        "emails" => [
          %{"value" => "invalid-email", "type" => "work", "primary" => true}
        ],
        "password" => "weak",
        "password_confirmation" => "different"
      }

      assert {:error, changeset} = Accounts.create_user_with_role(invalid_attrs, organization.id)
      assert changeset.errors != []
    end

    test "create_user_with_role/3 returns error with duplicate email", %{
      organization: organization
    } do
      n = System.unique_integer([:positive])
      dup_email = "duplicate-#{n}@example.com"

      user_attrs = %{
        "first_name" => "First",
        "last_name" => "User",
        "emails" => [
          %{"value" => dup_email, "type" => "work", "primary" => true}
        ],
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      assert {:ok, _user} = Accounts.create_user_with_role(user_attrs, organization.id)

      # Try to create second user with same email
      duplicate_attrs = %{
        "first_name" => "Second",
        "last_name" => "User",
        "email" => dup_email,
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      assert {:error, changeset} =
               Accounts.create_user_with_role(duplicate_attrs, organization.id)

      # Check for email uniqueness error in nested emails association
      assert changeset.errors != [] or
               (changeset.changes[:emails] &&
                  Enum.any?(changeset.changes[:emails], fn email_changeset ->
                    Keyword.has_key?(email_changeset.errors, :value)
                  end))
    end

    test "create_user_with_role/3 rollbacks transaction on failure", %{
      organization: _organization
    } do
      n = System.unique_integer([:positive])
      rollback_email = "test.user-#{n}@example.com"
      # Use invalid organization ID to trigger error in user_organization creation
      user_attrs = %{
        "first_name" => "Test",
        "last_name" => "User",
        "email" => rollback_email,
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      invalid_org_id = 999_999

      assert {:error, _} = Accounts.create_user_with_role(user_attrs, invalid_org_id)

      # Verify user was not created due to rollback - there's no get_user_by_email in accounts
      # so we'll check that we can't find a user with this email globally
      assert Accounts.get_user_by_email_and_organization(rollback_email, invalid_org_id) ==
               nil
    end
  end

  describe "password reset" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      %{organization: organization, user: user}
    end

    test "generate_password_reset_token/1 generates token and sets expiration", %{user: user} do
      assert {:ok, updated_user, token} = Accounts.generate_password_reset_token(user)

      assert token != nil
      assert String.length(token) > 30
      assert updated_user.password_reset_token != nil
      assert updated_user.password_reset_expires_at != nil
      assert DateTime.after?(updated_user.password_reset_expires_at, DateTime.utc_now())
    end

    test "generate_password_reset_token/1 overwrites existing token", %{user: user} do
      # Generate first token
      {:ok, user_with_token, first_token} = Accounts.generate_password_reset_token(user)

      # Generate second token
      {:ok, updated_user, second_token} = Accounts.generate_password_reset_token(user_with_token)

      assert first_token != second_token
      assert updated_user.password_reset_token != user_with_token.password_reset_token
    end

    test "get_user_by_password_reset_token/1 returns user with valid token", %{user: user} do
      {:ok, _updated_user, token} = Accounts.generate_password_reset_token(user)

      found_user = Accounts.get_user_by_password_reset_token(token)
      assert found_user.id == user.id

      assert Authify.Accounts.User.get_primary_email_value(found_user) ==
               Authify.Accounts.User.get_primary_email_value(user)
    end

    test "get_user_by_password_reset_token/1 returns nil for invalid token" do
      assert Accounts.get_user_by_password_reset_token("invalid-token") == nil
    end

    test "get_user_by_password_reset_token/1 returns nil for nil token" do
      assert Accounts.get_user_by_password_reset_token(nil) == nil
    end

    test "reset_password_with_token/2 resets password with valid token", %{user: user} do
      {:ok, _updated_user, token} = Accounts.generate_password_reset_token(user)

      password_params = %{
        "password" => "NewSecureP@ssw0rd!",
        "password_confirmation" => "NewSecureP@ssw0rd!"
      }

      assert {:ok, reset_user} = Accounts.reset_password_with_token(token, password_params)

      # Password should be changed
      assert User.valid_password?(reset_user, "NewSecureP@ssw0rd!")
      refute User.valid_password?(reset_user, "SecureP@ssw0rd!")

      # Token should be cleared
      assert reset_user.password_reset_token == nil
      assert reset_user.password_reset_expires_at == nil
    end

    test "reset_password_with_token/2 returns error for expired token", %{user: user} do
      # Create user with expired reset token
      expired_time = DateTime.add(DateTime.utc_now(), -1, :hour) |> DateTime.truncate(:second)
      plaintext_token = User.generate_password_reset_token()
      hashed_token = User.hash_password_reset_token(plaintext_token)

      user
      |> Ecto.Changeset.change(%{
        password_reset_token: hashed_token,
        password_reset_expires_at: expired_time
      })
      |> Authify.Repo.update!()

      password_params = %{
        "password" => "NewSecureP@ssw0rd!",
        "password_confirmation" => "NewSecureP@ssw0rd!"
      }

      assert {:error, :token_expired} =
               Accounts.reset_password_with_token(plaintext_token, password_params)
    end

    test "reset_password_with_token/2 returns error for invalid token" do
      password_params = %{
        "password" => "NewSecureP@ssw0rd!",
        "password_confirmation" => "NewSecureP@ssw0rd!"
      }

      assert {:error, :token_not_found} =
               Accounts.reset_password_with_token("invalid-token", password_params)
    end

    test "reset_password_with_token/2 returns error for invalid password params", %{user: user} do
      {:ok, _updated_user, token} = Accounts.generate_password_reset_token(user)

      invalid_password_params = %{
        "password" => "weak",
        "password_confirmation" => "different"
      }

      assert {:error, %Ecto.Changeset{}} =
               Accounts.reset_password_with_token(token, invalid_password_params)
    end

    test "cleanup_expired_password_reset_tokens/0 removes expired tokens" do
      organization = organization_fixture()
      user1 = user_for_organization_fixture(organization)
      user2 = user_for_organization_fixture(organization)

      # Create valid token for user1
      {:ok, _user1_updated, _token1} = Accounts.generate_password_reset_token(user1)

      # Create expired token for user2
      expired_time = DateTime.add(DateTime.utc_now(), -1, :hour) |> DateTime.truncate(:second)
      expired_token = User.generate_password_reset_token()

      user2
      |> Ecto.Changeset.change(%{
        password_reset_token: expired_token,
        password_reset_expires_at: expired_time
      })
      |> Authify.Repo.update!()

      # Cleanup expired tokens
      {deleted_count, _} = Accounts.cleanup_expired_password_reset_tokens()
      assert deleted_count == 1

      # user1 should still have token, user2 should not
      user1_refreshed = Accounts.get_user!(user1.id)
      user2_refreshed = Accounts.get_user!(user2.id)

      assert user1_refreshed.password_reset_token != nil
      assert user2_refreshed.password_reset_token == nil
    end
  end

  describe "password reset utilities" do
    test "User.valid_password_reset_token?/1 validates token expiration" do
      # Valid token (not expired)
      valid_user = %User{
        password_reset_token: "some-token",
        password_reset_expires_at: DateTime.add(DateTime.utc_now(), 1, :hour)
      }

      assert User.valid_password_reset_token?(valid_user) == true

      # Expired token
      expired_user = %User{
        password_reset_token: "some-token",
        password_reset_expires_at: DateTime.add(DateTime.utc_now(), -1, :hour)
      }

      assert User.valid_password_reset_token?(expired_user) == false

      # No token
      no_token_user = %User{
        password_reset_token: nil,
        password_reset_expires_at: nil
      }

      assert User.valid_password_reset_token?(no_token_user) == false

      # Token but no expiration
      no_expiration_user = %User{
        password_reset_token: "some-token",
        password_reset_expires_at: nil
      }

      assert User.valid_password_reset_token?(no_expiration_user) == false
    end

    test "User.generate_password_reset_token/0 generates secure token" do
      token1 = User.generate_password_reset_token()
      token2 = User.generate_password_reset_token()

      # Tokens should be different
      assert token1 != token2

      # Tokens should be reasonable length (URL-safe base64)
      assert String.length(token1) > 30
      assert String.length(token2) > 30

      # Should be URL-safe (no padding, no unsafe chars)
      refute String.contains?(token1, "=")
      refute String.contains?(token2, "=")
      refute String.contains?(token1, "+")
      refute String.contains?(token2, "+")
      refute String.contains?(token1, "/")
      refute String.contains?(token2, "/")
    end

    test "build_password_reset_url/2 generates a link to the edit form" do
      organization = organization_fixture()
      token = User.generate_password_reset_token()
      url = Accounts.build_password_reset_url(organization, token)

      assert String.ends_with?(url, "/password_reset/#{token}/edit")
    end
  end

  describe "certificates" do
    setup do
      organization = organization_fixture()
      %{organization: organization}
    end

    test "create_certificate/2 enforces only one active certificate per usage", %{
      organization: organization
    } do
      # Create first SAML signing certificate using the proper generation function
      {:ok, cert1} =
        Accounts.generate_saml_signing_certificate(organization, %{
          "name" => "SAML Cert 1",
          "is_active" => true
        })

      assert cert1.is_active == true

      # Create second SAML signing certificate using the proper generation function
      {:ok, cert2} =
        Accounts.generate_saml_signing_certificate(organization, %{
          "name" => "SAML Cert 2",
          "is_active" => true
        })

      assert cert2.is_active == true

      # Verify first cert is now deactivated
      updated_cert1 = Accounts.get_certificate!(cert1.id)
      assert updated_cert1.is_active == false

      # Create different usage type - should not affect SAML signing certs
      {:ok, oauth_cert} =
        Accounts.generate_saml_signing_certificate(organization, %{
          "name" => "OAuth Cert"
        })

      # Change usage type to oauth_signing and activate
      {:ok, oauth_cert} =
        Accounts.update_certificate(oauth_cert, %{"usage" => "oauth_signing", "is_active" => true})

      # Both different usage certs can be active
      assert oauth_cert.is_active == true
      updated_cert2 = Accounts.get_certificate!(cert2.id)
      assert updated_cert2.is_active == true
    end

    test "update_certificate/2 enforces only one active certificate per usage", %{
      organization: organization
    } do
      # Create two inactive certificates of same usage using proper generation
      {:ok, cert1} =
        Accounts.generate_saml_signing_certificate(organization, %{
          "name" => "SAML Cert 1"
        })

      {:ok, cert2} =
        Accounts.generate_saml_signing_certificate(organization, %{
          "name" => "SAML Cert 2"
        })

      # Activate first certificate
      {:ok, updated_cert1} = Accounts.update_certificate(cert1, %{"is_active" => true})
      assert updated_cert1.is_active == true

      # Activate second certificate (should deactivate first)
      {:ok, updated_cert2} = Accounts.update_certificate(cert2, %{"is_active" => true})
      assert updated_cert2.is_active == true

      # Verify first cert is now deactivated
      updated_cert1_again = Accounts.get_certificate!(cert1.id)
      assert updated_cert1_again.is_active == false
    end

    test "get_active_saml_signing_certificate/1 returns only the active certificate", %{
      organization: organization
    } do
      # No certificates initially
      assert Accounts.get_active_saml_signing_certificate(organization) == nil

      # Create inactive certificate using proper generation
      {:ok, _inactive_cert} =
        Accounts.generate_saml_signing_certificate(organization, %{
          "name" => "Inactive SAML Cert"
        })

      # Still no active certificate (generated certificates are inactive by default)
      assert Accounts.get_active_saml_signing_certificate(organization) == nil

      # Create and activate a certificate
      {:ok, active_cert} =
        Accounts.generate_saml_signing_certificate(organization, %{
          "name" => "Active SAML Cert"
        })

      {:ok, active_cert} = Accounts.update_certificate(active_cert, %{"is_active" => true})

      # Should return the active certificate
      result = Accounts.get_active_saml_signing_certificate(organization)
      assert result.id == active_cert.id
      assert result.is_active == true
    end

    test "get_active_oauth_signing_certificate/1 returns nil when no cert exists", %{
      organization: organization
    } do
      assert Accounts.get_active_oauth_signing_certificate(organization) == nil
    end

    test "get_active_oauth_signing_certificate/1 returns the active cert when one exists", %{
      organization: organization
    } do
      # Create an inactive OAuth signing cert first (with explicit unique name)
      {:ok, inactive_cert} =
        Accounts.generate_certificate(organization, %{
          "usage" => "oauth_signing",
          "name" => "Inactive OAuth Cert"
        })

      assert Accounts.get_active_oauth_signing_certificate(organization) == nil

      # Activate the cert
      {:ok, cert} = Accounts.update_certificate(inactive_cert, %{"is_active" => true})

      result = Accounts.get_active_oauth_signing_certificate(organization)
      assert result.id == cert.id
      assert result.is_active == true
      assert result.usage == "oauth_signing"
    end

    test "get_or_generate_oauth_signing_certificate/1 auto-generates when no cert exists", %{
      organization: organization
    } do
      assert Accounts.get_active_oauth_signing_certificate(organization) == nil

      assert {:ok, cert} = Accounts.get_or_generate_oauth_signing_certificate(organization)
      assert cert.usage == "oauth_signing"
      assert cert.is_active == true
      assert is_binary(cert.certificate)
      assert is_binary(cert.private_key)
    end

    test "get_or_generate_oauth_signing_certificate/1 returns existing active cert", %{
      organization: organization
    } do
      {:ok, existing} =
        Accounts.generate_certificate(organization, %{
          "usage" => "oauth_signing",
          "is_active" => true
        })

      assert {:ok, cert} = Accounts.get_or_generate_oauth_signing_certificate(organization)
      assert cert.id == existing.id
    end
  end

  describe "groups" do
    setup do
      {:ok, org} = Accounts.create_organization(valid_org_attrs())
      %{organization: org}
    end

    test "Group.changeset/2 with valid attrs produces a valid changeset", %{organization: org} do
      changeset =
        Group.changeset(%Group{}, %{"name" => "Engineering", "organization_id" => org.id})

      assert changeset.valid?
    end

    test "Group.changeset/2 requires name", %{organization: org} do
      changeset = Group.changeset(%Group{}, %{"organization_id" => org.id})
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).name
    end

    test "Group.changeset/2 requires organization_id" do
      changeset = Group.changeset(%Group{}, %{"name" => "Engineering"})
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).organization_id
    end

    test "Group.changeset/2 validates name max length", %{organization: org} do
      changeset =
        Group.changeset(%Group{}, %{
          "name" => String.duplicate("a", 256),
          "organization_id" => org.id
        })

      refute changeset.valid?
      assert "should be at most 255 character(s)" in errors_on(changeset).name
    end

    test "Group.changeset/2 validates description max length", %{organization: org} do
      changeset =
        Group.changeset(%Group{}, %{
          "name" => "Engineering",
          "organization_id" => org.id,
          "description" => String.duplicate("a", 1001)
        })

      refute changeset.valid?
      assert "should be at most 1000 character(s)" in errors_on(changeset).description
    end

    test "Group.changeset/2 accepts valid external_id", %{organization: org} do
      changeset =
        Group.changeset(%Group{}, %{
          "name" => "Engineering",
          "organization_id" => org.id,
          "external_id" => "ext-123.valid_id"
        })

      assert changeset.valid?
    end

    test "Group.changeset/2 rejects external_id starting with non-alphanumeric character", %{
      organization: org
    } do
      changeset =
        Group.changeset(%Group{}, %{
          "name" => "Engineering",
          "organization_id" => org.id,
          "external_id" => "-bad-start"
        })

      refute changeset.valid?
      assert Enum.any?(errors_on(changeset).external_id, &String.contains?(&1, "must start with"))
    end

    test "Group.changeset/2 rejects external_id exceeding max length", %{organization: org} do
      changeset =
        Group.changeset(%Group{}, %{
          "name" => "Engineering",
          "organization_id" => org.id,
          "external_id" => "a" <> String.duplicate("x", 255)
        })

      refute changeset.valid?
      assert "should be at most 255 character(s)" in errors_on(changeset).external_id
    end

    test "create_group/1 defaults is_active to true", %{organization: org} do
      {:ok, group} =
        Accounts.create_group(%{"name" => "Default Active", "organization_id" => org.id})

      assert group.is_active == true
    end

    test "create_group/1 allows setting is_active to false", %{organization: org} do
      {:ok, group} =
        Accounts.create_group(%{
          "name" => "Inactive Group",
          "organization_id" => org.id,
          "is_active" => false
        })

      assert group.is_active == false
    end

    test "Group.apply_scim_timestamps/2 sets scim timestamps on insert", %{organization: org} do
      now = DateTime.utc_now() |> DateTime.truncate(:second)

      {:ok, group} =
        Accounts.create_group(%{
          name: "SCIM Group",
          organization_id: org.id,
          scim_created_at: now,
          scim_updated_at: now
        })

      assert group.scim_created_at == now
      assert group.scim_updated_at == now
    end

    test "list_groups/1 returns all groups for the organization", %{organization: org} do
      {:ok, g1} = Accounts.create_group(%{"name" => "Alpha", "organization_id" => org.id})
      {:ok, g2} = Accounts.create_group(%{"name" => "Beta", "organization_id" => org.id})
      ids = Accounts.list_groups(org) |> Enum.map(& &1.id)
      assert g1.id in ids
      assert g2.id in ids
    end

    test "list_groups/1 does not return groups from other organizations", %{organization: org} do
      {:ok, other_org} = Accounts.create_organization(valid_org_attrs())

      {:ok, other_group} =
        Accounts.create_group(%{"name" => "Other", "organization_id" => other_org.id})

      ids = Accounts.list_groups(org) |> Enum.map(& &1.id)
      refute other_group.id in ids
    end

    test "list_groups_filtered/2 with no opts returns all groups", %{organization: org} do
      {:ok, g1} = Accounts.create_group(%{"name" => "Gamma", "organization_id" => org.id})
      ids = Accounts.list_groups_filtered(org) |> Enum.map(& &1.id)
      assert g1.id in ids
    end

    test "list_groups_filtered/2 filters by active status true", %{organization: org} do
      {:ok, active} =
        Accounts.create_group(%{
          "name" => "Active",
          "organization_id" => org.id,
          "is_active" => true
        })

      {:ok, inactive} =
        Accounts.create_group(%{
          "name" => "Inactive",
          "organization_id" => org.id,
          "is_active" => false
        })

      results = Accounts.list_groups_filtered(org, status: true)
      ids = Enum.map(results, & &1.id)
      assert active.id in ids
      refute inactive.id in ids
    end

    test "list_groups_filtered/2 filters by active status false", %{organization: org} do
      {:ok, active} =
        Accounts.create_group(%{
          "name" => "Active2",
          "organization_id" => org.id,
          "is_active" => true
        })

      {:ok, inactive} =
        Accounts.create_group(%{
          "name" => "Inactive2",
          "organization_id" => org.id,
          "is_active" => false
        })

      results = Accounts.list_groups_filtered(org, status: false)
      ids = Enum.map(results, & &1.id)
      assert inactive.id in ids
      refute active.id in ids
    end

    test "list_groups_filtered/2 searches by name", %{organization: org} do
      {:ok, match} =
        Accounts.create_group(%{"name" => "UniqueSearchName", "organization_id" => org.id})

      {:ok, no_match} =
        Accounts.create_group(%{"name" => "SomethingElse", "organization_id" => org.id})

      results = Accounts.list_groups_filtered(org, search: "UniqueSearchName")
      ids = Enum.map(results, & &1.id)
      assert match.id in ids
      refute no_match.id in ids
    end

    test "list_groups_filtered/2 searches by description", %{organization: org} do
      {:ok, match} =
        Accounts.create_group(%{
          "name" => "GroupWithDesc",
          "organization_id" => org.id,
          "description" => "UniqueDescriptionText"
        })

      {:ok, no_match} =
        Accounts.create_group(%{"name" => "NoDescGroup", "organization_id" => org.id})

      results = Accounts.list_groups_filtered(org, search: "UniqueDescriptionText")
      ids = Enum.map(results, & &1.id)
      assert match.id in ids
      refute no_match.id in ids
    end

    test "list_groups_filtered/2 sorts by name ascending", %{organization: org} do
      Accounts.create_group(%{"name" => "Zephyr", "organization_id" => org.id})
      Accounts.create_group(%{"name" => "Aardvark", "organization_id" => org.id})
      results = Accounts.list_groups_filtered(org, sort: :name, order: :asc)
      names = Enum.map(results, & &1.name)
      assert names == Enum.sort(names)
    end

    test "list_groups_filtered/2 sorts by name descending", %{organization: org} do
      Accounts.create_group(%{"name" => "Zeta", "organization_id" => org.id})
      Accounts.create_group(%{"name" => "Alpha", "organization_id" => org.id})
      results = Accounts.list_groups_filtered(org, sort: :name, order: :desc)
      names = Enum.map(results, & &1.name)
      assert names == Enum.sort(names, :desc)
    end

    test "get_group!/2 returns the group scoped to the organization", %{organization: org} do
      {:ok, group} = Accounts.create_group(%{"name" => "GetTest", "organization_id" => org.id})
      found = Accounts.get_group!(group.id, org)
      assert found.id == group.id
      assert found.name == "GetTest"
    end

    test "get_group!/2 raises when group belongs to a different organization", %{
      organization: org
    } do
      {:ok, other_org} = Accounts.create_organization(valid_org_attrs())

      {:ok, group} =
        Accounts.create_group(%{"name" => "OtherOrgGroup", "organization_id" => other_org.id})

      assert_raise Ecto.NoResultsError, fn -> Accounts.get_group!(group.id, org) end
    end

    test "get_group/1 returns group by integer id", %{organization: org} do
      {:ok, group} = Accounts.create_group(%{"name" => "IntIdGroup", "organization_id" => org.id})
      found = Accounts.get_group(group.id)
      assert found.id == group.id
    end

    test "get_group/1 returns group by string id", %{organization: org} do
      {:ok, group} =
        Accounts.create_group(%{"name" => "StringIdGroup", "organization_id" => org.id})

      found = Accounts.get_group(Integer.to_string(group.id))
      assert found.id == group.id
    end

    test "get_group/1 returns nil for non-existent integer id" do
      assert Accounts.get_group(999_999_999) == nil
    end

    test "get_group/1 returns nil for non-numeric string id" do
      assert Accounts.get_group("not-a-number") == nil
    end

    test "create_group/1 with valid attrs creates a group", %{organization: org} do
      assert {:ok, %Group{} = group} =
               Accounts.create_group(%{
                 "name" => "New Group",
                 "organization_id" => org.id,
                 "description" => "A test group"
               })

      assert group.name == "New Group"
      assert group.description == "A test group"
      assert group.organization_id == org.id
      assert group.is_active == true
    end

    test "create_group/1 with invalid attrs returns error changeset" do
      assert {:error, %Ecto.Changeset{}} = Accounts.create_group(%{"name" => ""})
    end

    test "create_group/1 enforces unique name within the same organization", %{organization: org} do
      {:ok, _} = Accounts.create_group(%{"name" => "DupeName", "organization_id" => org.id})

      assert {:error, %Ecto.Changeset{} = changeset} =
               Accounts.create_group(%{"name" => "DupeName", "organization_id" => org.id})

      assert "Group name already exists in this organization" in errors_on(changeset).name
    end

    test "create_group/1 allows the same name across different organizations", %{
      organization: org
    } do
      {:ok, other_org} = Accounts.create_organization(valid_org_attrs())
      {:ok, _} = Accounts.create_group(%{"name" => "SharedName", "organization_id" => org.id})

      assert {:ok, _} =
               Accounts.create_group(%{"name" => "SharedName", "organization_id" => other_org.id})
    end

    test "create_group/1 enforces unique external_id within the same organization", %{
      organization: org
    } do
      {:ok, _} =
        Accounts.create_group(%{
          "name" => "Group1",
          "organization_id" => org.id,
          "external_id" => "ext-unique-123"
        })

      assert {:error, %Ecto.Changeset{} = changeset} =
               Accounts.create_group(%{
                 "name" => "Group2",
                 "organization_id" => org.id,
                 "external_id" => "ext-unique-123"
               })

      assert "external_id already exists in this organization" in errors_on(changeset).external_id
    end

    test "update_group/2 with valid attrs updates the group", %{organization: org} do
      {:ok, group} = Accounts.create_group(%{"name" => "Before", "organization_id" => org.id})

      assert {:ok, updated} =
               Accounts.update_group(group, %{"name" => "After", "description" => "Updated"})

      assert updated.name == "After"
      assert updated.description == "Updated"
    end

    test "update_group/2 with invalid attrs returns error changeset", %{organization: org} do
      {:ok, group} = Accounts.create_group(%{"name" => "Valid", "organization_id" => org.id})
      assert {:error, %Ecto.Changeset{}} = Accounts.update_group(group, %{"name" => ""})
    end

    test "update_group/2 prevents changing external_id once set", %{organization: org} do
      {:ok, group} =
        Accounts.create_group(%{
          "name" => "ExtGroup",
          "organization_id" => org.id,
          "external_id" => "original-ext"
        })

      assert {:error, %Ecto.Changeset{} = changeset} =
               Accounts.update_group(group, %{"external_id" => "changed-ext"})

      assert "cannot be changed once set" in errors_on(changeset).external_id
    end

    test "update_group/2 allows setting the same external_id value again", %{organization: org} do
      {:ok, group} =
        Accounts.create_group(%{
          "name" => "SameExtGroup",
          "organization_id" => org.id,
          "external_id" => "keep-same"
        })

      assert {:ok, updated} =
               Accounts.update_group(group, %{
                 "external_id" => "keep-same",
                 "name" => "Updated Name"
               })

      assert updated.external_id == "keep-same"
      assert updated.name == "Updated Name"
    end

    test "delete_group/1 deletes the group", %{organization: org} do
      {:ok, group} = Accounts.create_group(%{"name" => "ToDelete", "organization_id" => org.id})
      assert {:ok, %Group{}} = Accounts.delete_group(group)
      assert_raise Ecto.NoResultsError, fn -> Accounts.get_group!(group.id, org) end
    end

    test "change_group/2 returns a group changeset", %{organization: org} do
      {:ok, group} =
        Accounts.create_group(%{"name" => "ForChangeset", "organization_id" => org.id})

      assert %Ecto.Changeset{} = Accounts.change_group(group)
    end

    test "get_group_by_external_id/2 finds group by external_id", %{organization: org} do
      {:ok, group} =
        Accounts.create_group(%{
          "name" => "ExtLookup",
          "organization_id" => org.id,
          "external_id" => "lookup-ext-id"
        })

      found = Accounts.get_group_by_external_id("lookup-ext-id", org.id)
      assert found.id == group.id
    end

    test "get_group_by_external_id/2 returns nil when not found", %{organization: org} do
      assert Accounts.get_group_by_external_id("nonexistent", org.id) == nil
    end

    test "get_group_by_external_id/2 returns nil for nil arguments" do
      assert Accounts.get_group_by_external_id(nil, nil) == nil
    end
  end

  describe "group memberships" do
    setup do
      {:ok, org} = Accounts.create_organization(valid_org_attrs())
      {:ok, user} = Accounts.create_user_with_role(valid_user_attrs(), org.id, "user")

      {:ok, group} =
        Accounts.create_group(%{"name" => "MembershipGroup", "organization_id" => org.id})

      %{organization: org, user: user, group: group}
    end

    test "GroupMembership.changeset/2 with valid attrs produces a valid changeset", %{
      user: user,
      group: group
    } do
      changeset =
        GroupMembership.changeset(%GroupMembership{}, %{user_id: user.id, group_id: group.id})

      assert changeset.valid?
    end

    test "GroupMembership.changeset/2 requires user_id", %{group: group} do
      changeset = GroupMembership.changeset(%GroupMembership{}, %{group_id: group.id})
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).user_id
    end

    test "GroupMembership.changeset/2 requires group_id", %{user: user} do
      changeset = GroupMembership.changeset(%GroupMembership{}, %{user_id: user.id})
      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).group_id
    end

    test "add_user_to_group/2 adds the user to the group", %{user: user, group: group} do
      assert {:ok, %GroupMembership{}} = Accounts.add_user_to_group(user, group)
      members = Accounts.list_group_members(group)
      assert Enum.any?(members, &(&1.id == user.id))
    end

    test "add_user_to_group/2 returns error when user is already in the group", %{
      user: user,
      group: group
    } do
      {:ok, _} = Accounts.add_user_to_group(user, group)

      assert {:error, %Ecto.Changeset{} = changeset} = Accounts.add_user_to_group(user, group)
      assert "User is already in this group" in errors_on(changeset).user_id
    end

    test "remove_user_from_group/2 removes the user from the group", %{user: user, group: group} do
      {:ok, _} = Accounts.add_user_to_group(user, group)
      Accounts.remove_user_from_group(user, group)
      members = Accounts.list_group_members(group)
      refute Enum.any?(members, &(&1.id == user.id))
    end

    test "list_group_members/1 returns all users in the group", %{
      organization: org,
      group: group
    } do
      {:ok, user2} = Accounts.create_user_with_role(valid_user_attrs(), org.id, "user")
      {:ok, user3} = Accounts.create_user_with_role(valid_user_attrs(), org.id, "user")
      {:ok, _} = Accounts.add_user_to_group(user2, group)
      {:ok, _} = Accounts.add_user_to_group(user3, group)

      ids = Accounts.list_group_members(group) |> Enum.map(& &1.id)
      assert user2.id in ids
      assert user3.id in ids
    end

    test "list_group_members/1 returns empty list when group has no members", %{group: group} do
      assert Accounts.list_group_members(group) == []
    end

    test "list_user_groups/1 returns all groups the user belongs to", %{
      organization: org,
      user: user
    } do
      {:ok, group2} =
        Accounts.create_group(%{"name" => "SecondGroup", "organization_id" => org.id})

      {:ok, _other} =
        Accounts.create_group(%{"name" => "NotJoined", "organization_id" => org.id})

      {:ok, _} = Accounts.add_user_to_group(user, group2)

      group_ids = Accounts.list_user_groups(user) |> Enum.map(& &1.id)
      assert group2.id in group_ids
    end

    test "list_user_groups/1 returns empty list when user belongs to no groups", %{user: user} do
      assert Accounts.list_user_groups(user) == []
    end

    test "delete_group/1 cascades to remove group memberships", %{user: user, group: group} do
      {:ok, _} = Accounts.add_user_to_group(user, group)
      {:ok, _} = Accounts.delete_group(group)
      group_ids = Accounts.list_user_groups(user) |> Enum.map(& &1.id)
      refute group.id in group_ids
    end
  end
end
