defmodule Authify.Tasks.CleanupExpiredInvitationsTest do
  use Authify.DataCase, async: true

  alias Authify.Accounts.Invitation
  alias Authify.Repo
  alias Authify.Tasks.CleanupExpiredInvitations

  import Authify.AccountsFixtures

  describe "execute/1" do
    test "deletes invitations that expired more than 48 hours ago" do
      org = organization_fixture()
      inviter = admin_user_fixture(org)

      # Create an invitation that expired 3 days ago (should be deleted)
      old_expired_at = DateTime.utc_now() |> DateTime.add(-72, :hour)

      {:ok, old_invitation} =
        Authify.Accounts.create_invitation(%{
          "email" => "old@example.com",
          "role" => "user",
          "organization_id" => org.id,
          "invited_by_id" => inviter.id,
          "expires_at" => old_expired_at
        })

      # Create an invitation that expired 24 hours ago (should NOT be deleted)
      recent_expired_at = DateTime.utc_now() |> DateTime.add(-24, :hour)

      {:ok, recent_invitation} =
        Authify.Accounts.create_invitation(%{
          "email" => "recent@example.com",
          "role" => "user",
          "organization_id" => org.id,
          "invited_by_id" => inviter.id,
          "expires_at" => recent_expired_at
        })

      # Create a valid invitation (should NOT be deleted)
      valid_invitation = invitation_fixture()

      # Create an accepted invitation that's expired (should NOT be deleted)
      {:ok, accepted_invitation} =
        Authify.Accounts.create_invitation(%{
          "email" => "accepted@example.com",
          "role" => "user",
          "organization_id" => org.id,
          "invited_by_id" => inviter.id,
          "expires_at" => old_expired_at
        })

      Repo.update!(Invitation.changeset(accepted_invitation, %{accepted_at: DateTime.utc_now()}))

      # Execute the cleanup task
      task = %Authify.Tasks.Task{
        type: "cleanup_expired_invitations",
        action: "execute"
      }

      assert {:ok, results} = CleanupExpiredInvitations.execute(task)
      assert results.deleted_count == 1

      # Verify old invitation was deleted
      refute Repo.get(Invitation, old_invitation.id)

      # Verify recent expired invitation was NOT deleted (48-hour grace period)
      assert Repo.get(Invitation, recent_invitation.id)

      # Verify valid invitation was NOT deleted
      assert Repo.get(Invitation, valid_invitation.id)

      # Verify accepted invitation was NOT deleted (even though expired)
      assert Repo.reload(accepted_invitation)
    end

    test "returns zero count when no invitations to clean up" do
      task = %Authify.Tasks.Task{
        type: "cleanup_expired_invitations",
        action: "execute"
      }

      assert {:ok, results} = CleanupExpiredInvitations.execute(task)
      assert results.deleted_count == 0
    end

    test "logs cutoff time in results" do
      task = %Authify.Tasks.Task{
        type: "cleanup_expired_invitations",
        action: "execute"
      }

      assert {:ok, results} = CleanupExpiredInvitations.execute(task)
      assert %DateTime{} = results.cutoff
      assert %DateTime{} = results.completed_at

      # Cutoff should be approximately 48 hours ago
      expected_cutoff = DateTime.utc_now() |> DateTime.add(-48, :hour)
      diff = DateTime.diff(results.cutoff, expected_cutoff, :second)
      assert abs(diff) < 5
    end
  end

  describe "as_comparable_task/1" do
    test "returns singleton key to prevent concurrent executions" do
      task = %Authify.Tasks.Task{
        type: "cleanup_expired_invitations",
        action: "execute",
        organization_id: nil
      }

      assert CleanupExpiredInvitations.as_comparable_task(task) ==
               "cleanup_expired_invitations:singleton"
    end
  end

  describe "on_duplicate/2" do
    test "skips current task when a duplicate is found" do
      existing_task = %Authify.Tasks.Task{id: "existing-id", status: :running}
      current_task = %Authify.Tasks.Task{id: "current-id", status: :pending}

      assert CleanupExpiredInvitations.on_duplicate(existing_task, current_task) == :skip
    end
  end
end
