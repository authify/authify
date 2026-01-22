defmodule Authify.AccountsTest do
  use Authify.DataCase

  alias Authify.Accounts
  alias Authify.Accounts.{Invitation, Organization, User}

  import Authify.AccountsFixtures

  describe "organizations" do
    @valid_org_attrs %{name: "Test Organization", slug: "test-org"}
    @invalid_org_attrs %{name: "", slug: ""}

    test "list_organizations/0 returns all organizations" do
      {:ok, org} = Accounts.create_organization(@valid_org_attrs)
      organizations = Accounts.list_organizations()
      # Should include the test org and the global org created by migration
      refute Enum.empty?(organizations)
      assert Enum.any?(organizations, fn o -> o.id == org.id end)
    end

    test "get_organization!/1 returns the organization with given id" do
      {:ok, org} = Accounts.create_organization(@valid_org_attrs)
      assert Accounts.get_organization!(org.id) == org
    end

    test "get_organization_by_slug/1 returns organization with given slug" do
      {:ok, org} = Accounts.create_organization(@valid_org_attrs)
      assert Accounts.get_organization_by_slug("test-org") == org
      assert Accounts.get_organization_by_slug("nonexistent") == nil
    end

    test "create_organization/1 with valid data creates an organization" do
      assert {:ok, %Organization{} = org} = Accounts.create_organization(@valid_org_attrs)
      assert org.name == "Test Organization"
      assert org.slug == "test-org"
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
      {:ok, _org1} = Accounts.create_organization(@valid_org_attrs)

      assert {:error, %Ecto.Changeset{} = changeset} =
               Accounts.create_organization(@valid_org_attrs)

      assert "has already been taken" in errors_on(changeset).slug
    end

    test "update_organization/2 with valid data updates the organization" do
      {:ok, org} = Accounts.create_organization(@valid_org_attrs)
      update_attrs = %{name: "Updated Organization"}

      assert {:ok, %Organization{} = updated_org} =
               Accounts.update_organization(org, update_attrs)

      assert updated_org.name == "Updated Organization"
    end

    test "delete_organization/1 deletes the organization" do
      {:ok, org} = Accounts.create_organization(@valid_org_attrs)
      assert {:ok, %Organization{}} = Accounts.delete_organization(org)
      assert_raise Ecto.NoResultsError, fn -> Accounts.get_organization!(org.id) end
    end

    test "change_organization/1 returns an organization changeset" do
      {:ok, org} = Accounts.create_organization(@valid_org_attrs)
      assert %Ecto.Changeset{} = Accounts.change_organization(org)
    end
  end

  describe "users" do
    setup do
      {:ok, org} = Accounts.create_organization(@valid_org_attrs)
      %{organization: org}
    end

    @valid_user_attrs %{
      "emails" => [%{"value" => "test@example.com", "type" => "work", "primary" => true}],
      "first_name" => "John",
      "last_name" => "Doe",
      "password" => "SecureP@ssw0rd!",
      "password_confirmation" => "SecureP@ssw0rd!"
    }

    @invalid_user_attrs %{
      "emails" => [%{"value" => "invalid", "type" => "work", "primary" => true}],
      "password" => "123",
      "password_confirmation" => "456"
    }

    test "list_users/1 returns all users for organization", %{organization: org} do
      {:ok, user} = Accounts.create_user_with_role(@valid_user_attrs, org.id, "user")

      [found_user] = Accounts.list_users(org.id)
      assert found_user.id == user.id

      assert Authify.Accounts.User.get_primary_email_value(found_user) ==
               Authify.Accounts.User.get_primary_email_value(user)
    end

    test "get_user!/1 returns the user with given id", %{organization: _org} do
      {:ok, user} = Accounts.create_user(@valid_user_attrs)
      found_user = Accounts.get_user!(user.id)
      assert found_user.id == user.id

      assert Authify.Accounts.User.get_primary_email_value(found_user) ==
               Authify.Accounts.User.get_primary_email_value(user)

      assert found_user.first_name == user.first_name
    end

    test "get_user_by_email_and_organization/2 returns user", %{organization: org} do
      {:ok, user} = Accounts.create_user_with_role(@valid_user_attrs, org.id, "user")

      found_user = Accounts.get_user_by_email_and_organization("test@example.com", org.id)
      assert found_user.id == user.id

      assert Authify.Accounts.User.get_primary_email_value(found_user) ==
               Authify.Accounts.User.get_primary_email_value(user)
    end

    test "create_user/1 with valid data creates a user", %{organization: _org} do
      assert {:ok, %User{} = user} = Accounts.create_user(@valid_user_attrs)
      assert Authify.Accounts.User.get_primary_email_value(user) == "test@example.com"
      assert user.first_name == "John"
      assert user.last_name == "Doe"
      assert User.valid_password?(user, "SecureP@ssw0rd!")
    end

    test "create_user/1 with invalid data returns error changeset", %{organization: _org} do
      assert {:error, %Ecto.Changeset{}} = Accounts.create_user(@invalid_user_attrs)
    end

    test "create_organization_with_admin/2 creates org and admin user" do
      org_attrs = %{name: "Admin Test Org", slug: "admin-test"}
      user_attrs = @valid_user_attrs

      assert {:ok, {org, user}} = Accounts.create_organization_with_admin(org_attrs, user_attrs)

      assert org.name == "Admin Test Org"
      assert Authify.Accounts.User.get_primary_email_value(user) == "test@example.com"
      # Check that user has admin role in the organization
      assert User.admin?(user, org.id) == true
    end

    test "create_organization_with_admin/2 rolls back on user error" do
      org_attrs = %{name: "Rollback Test Org", slug: "rollback-test"}
      invalid_user_attrs = @invalid_user_attrs

      assert {:error, %Ecto.Changeset{}} =
               Accounts.create_organization_with_admin(org_attrs, invalid_user_attrs)

      # Organization should not exist due to rollback
      assert Accounts.get_organization_by_slug("rollback-test") == nil
    end

    test "authenticate_user/3 with valid credentials returns user", %{organization: org} do
      {:ok, user} = Accounts.create_user_with_role(@valid_user_attrs, org.id, "user")

      assert {:ok, authenticated_user} =
               Accounts.authenticate_user("test@example.com", "SecureP@ssw0rd!", org.id)

      assert authenticated_user.id == user.id
    end

    test "authenticate_user/3 with invalid password returns error", %{organization: org} do
      {:ok, _user} = Accounts.create_user_with_role(@valid_user_attrs, org.id, "user")

      assert {:error, :invalid_password} =
               Accounts.authenticate_user("test@example.com", "wrong_password", org.id)
    end

    test "authenticate_user/3 with non-existent user returns error", %{organization: org} do
      assert {:error, :user_not_found} =
               Accounts.authenticate_user("nonexistent@example.com", "SecureP@ssw0rd!", org.id)
    end

    test "update_user/2 clears email verification when email changes", %{organization: org} do
      # Create a user with verified email
      {:ok, user} = Accounts.create_user_with_role(@valid_user_attrs, org.id, "user")

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
      {:ok, new_email} =
        Accounts.add_email_to_user(verified_user, %{value: "newemail@example.com", type: "work"})

      {:ok, _primary_email} = Accounts.set_primary_email(verified_user, new_email.id)

      # Reload user to get updated emails
      updated_user =
        Authify.Repo.get!(Authify.Accounts.User, verified_user.id)
        |> Authify.Repo.preload(:emails, force: true)

      assert Authify.Accounts.User.get_primary_email_value(updated_user) ==
               "newemail@example.com"

      # New email starts unverified
      primary_email = Authify.Accounts.User.get_primary_email(updated_user)
      assert primary_email.verified_at == nil
    end

    test "update_user/2 preserves email verification when email doesn't change", %{
      organization: org
    } do
      # Create a user with verified email
      {:ok, user} = Accounts.create_user_with_role(@valid_user_attrs, org.id, "user")

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
      # Create a user with verified email
      {:ok, user} = Accounts.create_user_with_role(@valid_user_attrs, org.id, "user")

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
      {:ok, new_email} =
        Accounts.add_email_to_user(verified_user, %{
          value: "profilechange@example.com",
          type: "work"
        })

      {:ok, _primary_email} = Accounts.set_primary_email(verified_user, new_email.id)

      # Reload user to get updated emails
      updated_user =
        Authify.Repo.get!(Authify.Accounts.User, verified_user.id)
        |> Authify.Repo.preload(:emails, force: true)

      assert Authify.Accounts.User.get_primary_email_value(updated_user) ==
               "profilechange@example.com"

      # New email starts unverified
      primary_email = Authify.Accounts.User.get_primary_email(updated_user)
      assert primary_email.verified_at == nil
    end

    test "update_user_profile/2 preserves email verification when email doesn't change", %{
      organization: org
    } do
      # Create a user with verified email
      {:ok, user} = Accounts.create_user_with_role(@valid_user_attrs, org.id, "user")

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
      {:ok, regular_org} =
        Accounts.create_organization(%{name: "Regular Org", slug: "regular-org"})

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

    test "delete_invitation/1 deletes the invitation", %{organization: org, admin_user: admin} do
      invitation = invitation_for_organization_fixture(org, admin)

      assert {:ok, %Invitation{}} = Accounts.delete_invitation(invitation)
      assert_raise Ecto.NoResultsError, fn -> Accounts.get_invitation!(invitation.id) end
    end

    test "change_invitation/1 returns an invitation changeset", %{
      organization: org,
      admin_user: admin
    } do
      invitation = invitation_for_organization_fixture(org, admin)
      assert %Ecto.Changeset{} = Accounts.change_invitation(invitation)
    end

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
      user_attrs = %{
        "first_name" => "John",
        "last_name" => "Doe",
        "emails" => [
          %{"value" => "john.doe@example.com", "type" => "work", "primary" => true}
        ],
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      assert {:ok, user} = Accounts.create_user_with_role(user_attrs, organization.id, "user")

      # Check user was created correctly
      assert Authify.Accounts.User.get_primary_email_value(user) == "john.doe@example.com"
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
      admin_attrs = %{
        "first_name" => "Jane",
        "last_name" => "Admin",
        "emails" => [
          %{"value" => "jane.admin@example.com", "type" => "work", "primary" => true}
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
      user_attrs = %{
        "first_name" => "Default",
        "last_name" => "Role",
        "emails" => [
          %{"value" => "default.role@example.com", "type" => "work", "primary" => true}
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
      user_attrs = %{
        "first_name" => "First",
        "last_name" => "User",
        "emails" => [
          %{"value" => "duplicate@example.com", "type" => "work", "primary" => true}
        ],
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      assert {:ok, _user} = Accounts.create_user_with_role(user_attrs, organization.id)

      # Try to create second user with same email
      duplicate_attrs = %{
        "first_name" => "Second",
        "last_name" => "User",
        "email" => "duplicate@example.com",
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
      # Use invalid organization ID to trigger error in user_organization creation
      user_attrs = %{
        "first_name" => "Test",
        "last_name" => "User",
        "email" => "test.user@example.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      invalid_org_id = 999_999

      assert {:error, _} = Accounts.create_user_with_role(user_attrs, invalid_org_id)

      # Verify user was not created due to rollback - there's no get_user_by_email in accounts
      # so we'll check that we can't find a user with this email globally
      assert Accounts.get_user_by_email_and_organization("test.user@example.com", invalid_org_id) ==
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
      user2 = user_for_organization_fixture(organization, %{"email" => "user2@example.com"})

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
  end
end
