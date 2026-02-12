defmodule Authify.Tasks.EventHandlerTest do
  use Authify.DataCase, async: false
  use Oban.Testing, repo: Authify.Repo

  alias Authify.Tasks.EventHandler
  alias Authify.Tasks.Workers.TaskExecutor

  import Authify.AccountsFixtures

  setup do
    org = organization_fixture()
    %{org: org}
  end

  describe "handle_event/2" do
    test "creates and enqueues task for known event", %{org: org} do
      Oban.Testing.with_testing_mode(:manual, fn ->
        invitation = invitation_fixture(%{"organization_id" => org.id})

        params = %{
          invitation_id: invitation.id,
          organization_id: org.id
        }

        assert {:ok, task} = EventHandler.handle_event(:invite_created, params)

        assert task.type == "event"
        assert task.action == "invite_created"
        assert task.params[:invitation_id] == invitation.id
        assert task.organization_id == org.id
        assert task.status == :pending

        # Verify task was enqueued
        assert_enqueued(worker: TaskExecutor, args: %{"task_id" => task.id})
      end)
    end

    @tag :capture_log
    test "accepts organization_id as string key", %{org: org} do
      invitation = invitation_fixture(%{"organization_id" => org.id})

      params = %{
        "invitation_id" => invitation.id,
        "organization_id" => org.id
      }

      assert {:ok, task} = EventHandler.handle_event(:invite_created, params)
      assert task.organization_id == org.id
    end

    test "returns error for unknown event" do
      params = %{organization_id: 1}

      assert {:error, :unknown_event} = EventHandler.handle_event(:unknown_event, params)
    end

    test "returns error if task creation fails" do
      # Invalid organization_id (not an integer)
      params = %{invitation_id: "123", organization_id: "not_an_id"}

      assert {:error, changeset} = EventHandler.handle_event(:invite_created, params)
      refute changeset.valid?
    end
  end

  describe "event_tasks/0" do
    test "returns the event mapping with active handlers" do
      event_tasks = EventHandler.event_tasks()

      assert is_map(event_tasks)
      assert event_tasks[:invite_created] == Authify.Tasks.Event.InviteCreated

      assert event_tasks[:password_reset_requested] ==
               Authify.Tasks.Event.PasswordResetRequested

      assert event_tasks[:email_verification_needed] ==
               Authify.Tasks.Event.EmailVerificationNeeded
    end

    test "does not include unwired events" do
      event_tasks = EventHandler.event_tasks()

      refute Map.has_key?(event_tasks, :user_created)
      refute Map.has_key?(event_tasks, :user_deleted)
      refute Map.has_key?(event_tasks, :organization_created)
    end
  end
end
