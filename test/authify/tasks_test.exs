defmodule Authify.TasksTest do
  @moduledoc """
  Tests for the Tasks context module, covering CRUD, state transitions,
  queries, and task log operations.
  """
  use Authify.DataCase, async: true

  import Authify.AccountsFixtures

  alias Authify.Tasks
  alias Authify.Tasks.{Task, TaskLog}

  # --- Helpers ---

  defp task_attrs(overrides \\ %{}) do
    Map.merge(
      %{
        type: "email",
        action: "send_invitation",
        params: %{"user_id" => "123"}
      },
      overrides
    )
  end

  defp insert_task(overrides \\ %{}) do
    {:ok, task} = Tasks.create_task(task_attrs(overrides))
    task
  end

  # --- CRUD Tests ---

  describe "create_task/1" do
    test "creates a task with valid attributes" do
      attrs = task_attrs()
      assert {:ok, %Task{} = task} = Tasks.create_task(attrs)
      assert task.type == "email"
      assert task.action == "send_invitation"
      assert task.status == :pending
      assert task.params == %{"user_id" => "123"}
    end

    test "creates a task with organization association" do
      org = organization_fixture()
      attrs = task_attrs(%{organization_id: org.id})
      assert {:ok, %Task{} = task} = Tasks.create_task(attrs)
      assert task.organization_id == org.id
    end

    test "creates a task with parent association" do
      parent = insert_task()
      attrs = task_attrs(%{parent_id: parent.id})
      assert {:ok, %Task{} = child} = Tasks.create_task(attrs)
      assert child.parent_id == parent.id
    end

    test "returns error changeset with invalid attributes" do
      assert {:error, %Ecto.Changeset{}} = Tasks.create_task(%{})
    end
  end

  describe "get_task/1 and get_task!/1" do
    test "get_task/1 returns the task" do
      task = insert_task()
      assert %Task{} = found = Tasks.get_task(task.id)
      assert found.id == task.id
    end

    test "get_task/1 returns nil for non-existent task" do
      assert nil == Tasks.get_task(Ecto.UUID.generate())
    end

    test "get_task!/1 returns the task" do
      task = insert_task()
      assert %Task{} = found = Tasks.get_task!(task.id)
      assert found.id == task.id
    end

    test "get_task!/1 raises for non-existent task" do
      assert_raise Ecto.NoResultsError, fn ->
        Tasks.get_task!(Ecto.UUID.generate())
      end
    end
  end

  describe "update_task/2" do
    test "updates a task's attributes" do
      task = insert_task()
      assert {:ok, updated} = Tasks.update_task(task, %{priority: 5})
      assert updated.priority == 5
    end

    test "returns error changeset with invalid attributes" do
      task = insert_task()
      assert {:error, %Ecto.Changeset{}} = Tasks.update_task(task, %{priority: -1})
    end
  end

  describe "change_task/2" do
    test "returns a changeset" do
      task = insert_task()
      assert %Ecto.Changeset{} = Tasks.change_task(task)
    end
  end

  # --- State Transition Tests ---

  describe "transition_task/2" do
    test "transitions a pending task to running" do
      task = insert_task()
      assert {:ok, %Task{} = updated} = Tasks.transition_task(task, :running)
      assert updated.status == :running
      assert updated.started_at != nil
    end

    test "transitions running → completing → completed" do
      task = insert_task()
      {:ok, running} = Tasks.transition_task(task, :running)
      {:ok, completing} = Tasks.transition_task(running, :completing)
      {:ok, completed} = Tasks.transition_task(completing, :completed)
      assert completed.status == :completed
      assert completed.completed_at != nil
    end

    test "transitions running → failing → failed" do
      task = insert_task()
      {:ok, running} = Tasks.transition_task(task, :running)
      {:ok, failing} = Tasks.transition_task(running, :failing)
      {:ok, failed} = Tasks.transition_task(failing, :failed)
      assert failed.status == :failed
      assert failed.failed_at != nil
    end

    test "rejects invalid transitions" do
      task = insert_task()
      {:ok, running} = Tasks.transition_task(task, :running)
      {:ok, completing} = Tasks.transition_task(running, :completing)
      {:ok, completed} = Tasks.transition_task(completing, :completed)

      assert {:error, {:invalid_transition, :completed, :running}} =
               Tasks.transition_task(completed, :running)
    end
  end

  # --- Query Tests ---

  describe "list_tasks/2" do
    test "lists tasks for an organization" do
      org = organization_fixture()
      insert_task(%{organization_id: org.id, type: "email"})
      insert_task(%{organization_id: org.id, type: "scim"})

      # Task for a different org - should not appear
      other_org = organization_fixture()
      insert_task(%{organization_id: other_org.id})

      {tasks, total} = Tasks.list_tasks(org.id)
      assert length(tasks) == 2
      assert total == 2
    end

    test "filters tasks by status" do
      org = organization_fixture()
      task = insert_task(%{organization_id: org.id})
      insert_task(%{organization_id: org.id})
      Tasks.transition_task(task, :running)

      {pending_tasks, pending_count} = Tasks.list_tasks(org.id, status: :pending)
      assert pending_count == 1
      assert length(pending_tasks) == 1

      {running_tasks, running_count} = Tasks.list_tasks(org.id, status: :running)
      assert running_count == 1
      assert length(running_tasks) == 1
    end

    test "filters tasks by type" do
      org = organization_fixture()
      insert_task(%{organization_id: org.id, type: "email"})
      insert_task(%{organization_id: org.id, type: "scim"})

      {tasks, total} = Tasks.list_tasks(org.id, type: "email")
      assert total == 1
      assert hd(tasks).type == "email"
    end

    test "filters tasks by action" do
      org = organization_fixture()
      insert_task(%{organization_id: org.id, action: "send_invitation"})
      insert_task(%{organization_id: org.id, action: "sync_user"})

      {tasks, total} = Tasks.list_tasks(org.id, action: "sync_user")
      assert total == 1
      assert hd(tasks).action == "sync_user"
    end

    test "supports pagination" do
      org = organization_fixture()

      for i <- 1..5 do
        insert_task(%{organization_id: org.id, action: "action_#{i}"})
      end

      {page1, total} = Tasks.list_tasks(org.id, page: 1, per_page: 2)
      assert length(page1) == 2
      assert total == 5

      {page3, _total} = Tasks.list_tasks(org.id, page: 3, per_page: 2)
      assert length(page3) == 1
    end
  end

  describe "list_children/1" do
    test "lists child tasks of a parent" do
      parent = insert_task()
      child1 = insert_task(%{parent_id: parent.id, action: "step_1"})
      child2 = insert_task(%{parent_id: parent.id, action: "step_2"})

      # Unrelated task
      insert_task()

      children = Tasks.list_children(parent)
      child_ids = Enum.map(children, & &1.id)
      assert length(children) == 2
      assert child1.id in child_ids
      assert child2.id in child_ids
    end
  end

  describe "list_correlated_tasks/1" do
    test "lists tasks sharing a correlation ID" do
      correlation_id = Ecto.UUID.generate()
      insert_task(%{correlation_id: correlation_id, action: "step_1"})
      insert_task(%{correlation_id: correlation_id, action: "step_2"})
      insert_task(%{correlation_id: Ecto.UUID.generate()})

      tasks = Tasks.list_correlated_tasks(correlation_id)
      assert length(tasks) == 2
      assert Enum.all?(tasks, &(&1.correlation_id == correlation_id))
    end
  end

  describe "list_runnable_tasks/1" do
    test "returns pending tasks" do
      insert_task()
      insert_task()

      tasks = Tasks.list_runnable_tasks()
      assert length(tasks) >= 2
      assert Enum.all?(tasks, &(&1.status == :pending))
    end

    test "returns scheduled tasks past their scheduled_at" do
      past = DateTime.utc_now() |> DateTime.add(-60, :second) |> DateTime.truncate(:second)

      {:ok, task} =
        Tasks.create_task(task_attrs(%{status: :scheduled, scheduled_at: past}))

      tasks = Tasks.list_runnable_tasks()
      task_ids = Enum.map(tasks, & &1.id)
      assert task.id in task_ids
    end

    test "excludes scheduled tasks in the future" do
      future = DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.truncate(:second)

      {:ok, task} =
        Tasks.create_task(task_attrs(%{status: :scheduled, scheduled_at: future}))

      tasks = Tasks.list_runnable_tasks()
      task_ids = Enum.map(tasks, & &1.id)
      refute task.id in task_ids
    end

    test "respects the limit parameter" do
      for _ <- 1..5, do: insert_task()
      tasks = Tasks.list_runnable_tasks(2)
      assert length(tasks) <= 2
    end
  end

  # --- Task Cancellation Tests ---

  describe "cancel_task/1" do
    test "cancels a pending task" do
      task = insert_task()
      assert {:ok, cancelled} = Tasks.cancel_task(task)
      assert cancelled.status == :cancelled
    end

    test "cancels a running task" do
      task = insert_task()
      {:ok, running} = Tasks.transition_task(task, :running)
      assert {:ok, cancelled} = Tasks.cancel_task(running)
      assert cancelled.status == :cancelled
    end

    test "cancels a waiting task" do
      task = insert_task()
      {:ok, running} = Tasks.transition_task(task, :running)
      {:ok, waiting} = Tasks.transition_task(running, :waiting)
      assert {:ok, cancelled} = Tasks.cancel_task(waiting)
      assert cancelled.status == :cancelled
    end

    test "cancels a retrying task" do
      task = insert_task()
      {:ok, running} = Tasks.transition_task(task, :running)
      {:ok, retrying} = Tasks.transition_task(running, :retrying)
      assert {:ok, cancelled} = Tasks.cancel_task(retrying)
      assert cancelled.status == :cancelled
    end

    test "rejects cancellation of terminal tasks" do
      task = insert_task()
      {:ok, running} = Tasks.transition_task(task, :running)
      {:ok, completing} = Tasks.transition_task(running, :completing)
      {:ok, completed} = Tasks.transition_task(completing, :completed)

      assert {:error, {:invalid_transition, :completed, :cancelling}} =
               Tasks.cancel_task(completed)
    end

    test "cascades cancellation to child tasks" do
      parent = insert_task()
      child1 = insert_task(%{parent_id: parent.id, action: "step_1"})
      child2 = insert_task(%{parent_id: parent.id, action: "step_2"})

      # One child is already completed (should not be cancelled)
      {:ok, running} = Tasks.transition_task(child2, :running)
      {:ok, completing} = Tasks.transition_task(running, :completing)
      {:ok, _completed} = Tasks.transition_task(completing, :completed)

      assert {:ok, _cancelled_parent} = Tasks.cancel_task(parent)

      # Pending child should be cancelled
      assert Tasks.get_task!(child1.id).status == :cancelled
      # Completed child should remain completed
      assert Tasks.get_task!(child2.id).status == :completed
    end

    test "invokes before_cancel callback" do
      task = insert_task(%{type: "test_cancellable", action: "execute"})
      assert {:ok, _cancelled} = Tasks.cancel_task(task)
      assert_received {:before_cancel_called, _task_id}
    end
  end

  # --- Task Log Tests ---

  describe "create_task_log/2" do
    test "creates a log entry for a task" do
      task = insert_task()
      log_data = Jason.encode!([[1_234_567_890, "Task started"]])

      assert {:ok, %TaskLog{} = log} = Tasks.create_task_log(task, log_data)
      assert log.task_id == task.id
      assert log.log_data == log_data
    end
  end

  describe "list_task_logs/1" do
    test "returns logs for a task in order" do
      task = insert_task()
      Tasks.create_task_log(task, "Log entry 1")
      Tasks.create_task_log(task, "Log entry 2")

      logs = Tasks.list_task_logs(task)
      assert length(logs) == 2
      log_data = Enum.map(logs, & &1.log_data)
      assert "Log entry 1" in log_data
      assert "Log entry 2" in log_data
    end

    test "does not return logs for other tasks" do
      task1 = insert_task()
      task2 = insert_task(%{action: "other"})
      Tasks.create_task_log(task1, "Task 1 log")
      Tasks.create_task_log(task2, "Task 2 log")

      logs = Tasks.list_task_logs(task1)
      assert length(logs) == 1
      assert hd(logs).log_data == "Task 1 log"
    end
  end
end
