defmodule Authify.Tasks.EventHandlerTest do
  use Authify.DataCase, async: false
  use Oban.Testing, repo: Authify.Repo

  alias Authify.Tasks
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
        params = %{
          user_id: "user_123",
          organization_id: org.id
        }

        assert {:ok, task} = EventHandler.handle_event(:user_created, params)

        assert task.type == "event"
        assert task.action == "user_created"
        # Params have atom keys (original type is preserved, just sorted)
        assert task.params[:user_id] == "user_123"
        assert task.organization_id == org.id
        assert task.status == :pending

        # Verify task was enqueued
        assert_enqueued(worker: TaskExecutor, args: %{"task_id" => task.id})
      end)
    end

    test "accepts organization_id as string key", %{org: org} do
      params = %{
        "user_id" => "user_123",
        "organization_id" => org.id
      }

      assert {:ok, task} = EventHandler.handle_event(:user_created, params)
      assert task.organization_id == org.id
    end

    test "returns error for unknown event" do
      params = %{organization_id: 1}

      assert {:error, :unknown_event} = EventHandler.handle_event(:unknown_event, params)
    end

    test "returns error if task creation fails" do
      # Invalid organization_id (not an integer)
      params = %{user_id: "123", organization_id: "not_an_id"}

      assert {:error, changeset} = EventHandler.handle_event(:user_created, params)
      refute changeset.valid?
    end
  end

  describe "event_tasks/0" do
    test "returns the event mapping" do
      event_tasks = EventHandler.event_tasks()

      assert is_map(event_tasks)
      assert event_tasks[:user_created] == Authify.Tasks.Event.UserCreated
      assert event_tasks[:user_deleted] == Authify.Tasks.Event.UserDeleted

      assert event_tasks[:organization_created] ==
               Authify.Tasks.Event.OrganizationCreated
    end
  end

  describe "integration with event handlers" do
    test "event handler can create child tasks based on org config", %{org: org} do
      # This would be a real event handler that checks org settings
      # For now, we just verify the task gets created and executed automatically
      params = %{
        user_id: "user_123",
        organization_id: org.id
      }

      assert {:ok, task} = EventHandler.handle_event(:user_created, params)

      # In inline test mode, the task executes immediately
      # Verify it completed successfully
      completed = Tasks.get_task!(task.id)
      assert completed.status == :completed
      assert completed.results["event"] == "user_created"
      assert completed.results["user_id"] == "user_123"
    end
  end
end
