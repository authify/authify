defmodule Authify.Tasks.Workers.TaskExecutorTest do
  use Authify.DataCase, async: false

  import ExUnit.CaptureLog

  alias Authify.Tasks
  alias Authify.Tasks.Workers.TaskExecutor

  import Authify.AccountsFixtures

  setup do
    org = organization_fixture()
    %{org: org}
  end

  defp insert_task(org, attrs \\ %{}) do
    default = %{
      type: "test",
      action: "succeed",
      organization_id: org.id,
      params: %{}
    }

    {:ok, task} = Tasks.create_task(Map.merge(default, attrs))
    task
  end

  defp perform_task(task) do
    TaskExecutor.perform(%Oban.Job{args: %{"task_id" => task.id}})
  end

  # --- Happy Path ---

  describe "perform/1 - successful execution" do
    test "executes a pending task through to completion", %{org: org} do
      task = insert_task(org)

      assert :ok = perform_task(task)

      completed_task = Tasks.get_task!(task.id)
      assert completed_task.status == :completed
      assert completed_task.results == %{"result" => "success"}
      assert completed_task.started_at != nil
      assert completed_task.completed_at != nil
    end

    test "stores results from handler execution", %{org: org} do
      task = insert_task(org)
      assert :ok = perform_task(task)

      completed_task = Tasks.get_task!(task.id)
      assert completed_task.results == %{"result" => "success"}
    end
  end

  # --- Failure Path ---

  describe "perform/1 - failure handling" do
    test "fails a task when handler returns error", %{org: org} do
      task = insert_task(org, %{type: "test", action: "fail"})

      assert :ok = perform_task(task)

      failed_task = Tasks.get_task!(task.id)
      assert failed_task.status == :failed
      assert failed_task.failed_at != nil
      assert Map.has_key?(failed_task.errors, "final")
    end

    test "fails a task when handler raises an exception", %{org: org} do
      task = insert_task(org, %{type: "test", action: "raise"})

      assert :ok = perform_task(task)

      failed_task = Tasks.get_task!(task.id)
      assert failed_task.status == :failed
      assert failed_task.errors["final"]["type"] == "exception"
      assert failed_task.errors["final"]["message"] =~ "intentional exception"
    end

    test "fails with handler_not_found when module doesn't exist", %{org: org} do
      task = insert_task(org, %{type: "nonexistent", action: "handler"})

      assert :ok = perform_task(task)

      failed_task = Tasks.get_task!(task.id)
      assert failed_task.status == :failed
      assert failed_task.errors["final"]["type"] == "handler_not_found"
    end
  end

  # --- Retry Path ---

  describe "perform/1 - retry handling" do
    test "exhausts retries and fails when handler always fails (inline mode)", %{org: org} do
      task = insert_task(org, %{type: "test", action: "retryable_fail"})

      # In inline test mode, Oban executes retry jobs immediately, so all
      # retries are exhausted in a single perform call
      assert :ok = perform_task(task)

      failed_task = Tasks.get_task!(task.id)
      assert failed_task.status == :failed
      assert failed_task.retry_count == 3
      assert Map.has_key?(failed_task.errors, "attempt_1")
      assert Map.has_key?(failed_task.errors, "attempt_2")
      assert Map.has_key?(failed_task.errors, "attempt_3")
      assert Map.has_key?(failed_task.errors, "final")
    end

    test "fails permanently when should_retry? returns false", %{org: org} do
      task = insert_task(org, %{type: "test", action: "selective_retry"})

      assert :ok = perform_task(task)

      failed_task = Tasks.get_task!(task.id)
      assert failed_task.status == :failed
      assert failed_task.retry_count == 0
    end
  end

  # --- Lifecycle Hooks ---

  describe "perform/1 - lifecycle hooks" do
    test "calls on_success hook on successful completion", %{org: org} do
      task = insert_task(org, %{type: "test", action: "with_hooks"})

      assert :ok = perform_task(task)

      assert_received {:on_success_called, task_id, %{"result" => "with_hooks"}}
      assert task_id == task.id
    end

    test "calls on_failure hook on permanent failure", %{org: org} do
      task = insert_task(org, %{type: "test", action: "fail_with_hooks"})

      assert :ok = perform_task(task)

      assert_received {:on_failure_called, task_id, _reason}
      assert task_id == task.id
    end

    test "on_success can schedule a follow-up task", %{org: org} do
      task = insert_task(org, %{type: "test", action: "success_with_follow_up"})

      assert :ok = perform_task(task)

      completed_task = Tasks.get_task!(task.id)
      assert completed_task.status == :completed

      # Follow-up task should be created as a child
      children = Tasks.list_children(completed_task)
      assert length(children) == 1

      child = hd(children)
      assert child.type == "test"
      assert child.action == "succeed"
      assert child.parent_id == task.id
      assert child.organization_id == org.id
      assert child.params["follow_up"] == true
    end
  end

  # --- Exclusivity ---

  describe "perform/1 - exclusivity checking" do
    test "skips task when duplicate detected and policy is :skip", %{org: org} do
      # Create a running task that matches
      existing =
        insert_task(org, %{type: "test", action: "skip_duplicates", params: %{"key" => "val"}})

      {:ok, _running} = Tasks.transition_task(existing, :running)

      # Create a new task with same type/action/org/params
      duplicate =
        insert_task(org, %{type: "test", action: "skip_duplicates", params: %{"key" => "val"}})

      assert :ok = perform_task(duplicate)

      skipped_task = Tasks.get_task!(duplicate.id)
      assert skipped_task.status == :skipped
    end

    test "proceeds when no exclusivity checking (nil key)", %{org: org} do
      # Create a running task that would match
      existing =
        insert_task(org, %{type: "test", action: "no_exclusivity"})

      {:ok, _running} = Tasks.transition_task(existing, :running)

      # Create another task with same type/action
      new_task = insert_task(org, %{type: "test", action: "no_exclusivity"})

      assert :ok = perform_task(new_task)

      completed = Tasks.get_task!(new_task.id)
      assert completed.status == :completed
    end

    test "proceeds when no duplicates exist", %{org: org} do
      task = insert_task(org, %{type: "test", action: "succeed", params: %{"unique" => "data"}})

      assert :ok = perform_task(task)

      completed = Tasks.get_task!(task.id)
      assert completed.status == :completed
    end

    test "serializes exclusivity checks via ExclusivityLock" do
      alias Authify.Tasks.ExclusivityLock

      test_pid = self()
      lock_key = "test:serialization:key"

      # Track execution order
      holder =
        spawn_link(fn ->
          ExclusivityLock.with_lock(lock_key, fn ->
            send(test_pid, :first_acquired)

            receive do
              :release -> :ok
            end

            :first_result
          end)

          send(test_pid, :first_done)
        end)

      assert_receive :first_acquired, 1000

      # Second caller should block
      _waiter =
        spawn_link(fn ->
          result =
            ExclusivityLock.with_lock(lock_key, fn ->
              send(test_pid, :second_acquired)
              :second_result
            end)

          send(test_pid, {:second_done, result})
        end)

      # Second caller should NOT have acquired the lock yet
      refute_receive :second_acquired, 300

      # Release the first lock
      send(holder, :release)
      assert_receive :first_done, 1000

      # Now second caller should proceed
      assert_receive :second_acquired, 1000
      assert_receive {:second_done, :second_result}, 1000
    end

    test "allows concurrent execution for different keys" do
      alias Authify.Tasks.ExclusivityLock

      test_pid = self()

      # Two different keys should not block each other
      spawn_link(fn ->
        ExclusivityLock.with_lock("key_a", fn ->
          send(test_pid, :a_acquired)

          receive do
            :release_a -> :ok
          end
        end)
      end)

      assert_receive :a_acquired, 1000

      # Different key should proceed immediately
      spawn_link(fn ->
        ExclusivityLock.with_lock("key_b", fn ->
          send(test_pid, :b_acquired)

          receive do
            :release_b -> :ok
          end
        end)
      end)

      assert_receive :b_acquired, 1000
    end

    test "skips lock when exclusivity key is nil", %{org: org} do
      # NoExclusivity handler returns nil for as_comparable_task,
      # so no lock should be acquired. This task should complete
      # immediately regardless of any held locks.
      task = insert_task(org, %{type: "test", action: "no_exclusivity"})

      assert :ok = perform_task(task)

      completed = Tasks.get_task!(task.id)
      assert completed.status == :completed
    end
  end

  # --- State Handling ---

  describe "perform/1 - task state handling" do
    test "handles scheduled tasks by transitioning to pending first", %{org: org} do
      past = DateTime.add(DateTime.utc_now(), -60, :second) |> DateTime.truncate(:second)

      task =
        insert_task(org, %{
          status: :scheduled,
          scheduled_at: past
        })

      assert :ok = perform_task(task)

      completed = Tasks.get_task!(task.id)
      assert completed.status == :completed
    end

    test "returns :ok for task not found" do
      capture_log(fn ->
        assert :ok =
                 TaskExecutor.perform(%Oban.Job{
                   args: %{"task_id" => Ecto.UUID.generate()}
                 })
      end)
    end

    test "returns :ok for tasks in terminal states", %{org: org} do
      task = insert_task(org)
      {:ok, task} = Tasks.transition_task(task, :running)
      {:ok, task} = Tasks.transition_task(task, :completing)
      {:ok, _task} = Tasks.transition_task(task, :completed)

      capture_log(fn ->
        assert :ok = perform_task(Tasks.get_task!(task.id))
      end)
    end
  end

  # --- Scheduling ---

  describe "schedule_execution/2" do
    test "creates an Oban job for immediate execution", %{org: org} do
      task = insert_task(org)

      assert {:ok, %Oban.Job{} = job} = TaskExecutor.schedule_execution(task)
      assert job.args == %{"task_id" => task.id}
      assert job.queue == "tasks"
    end

    test "creates a delayed Oban job", %{org: org} do
      task = insert_task(org)

      assert {:ok, %Oban.Job{} = job} = TaskExecutor.schedule_execution(task, 60)
      assert job.args == %{"task_id" => task.id}
      assert job.scheduled_at != nil
    end
  end

  # --- Integration: create_and_enqueue_task ---

  describe "Tasks.create_and_enqueue_task/1" do
    test "creates a task and enqueues it", %{org: org} do
      attrs = %{
        type: "test",
        action: "succeed",
        organization_id: org.id,
        params: %{"key" => "value"}
      }

      assert {:ok, task} = Tasks.create_and_enqueue_task(attrs)
      assert task.status == :pending
      assert task.params == %{"key" => "value"}
    end

    test "returns error for invalid task attributes" do
      assert {:error, changeset} = Tasks.create_and_enqueue_task(%{})
      assert errors_on(changeset) |> Map.has_key?(:type)
    end
  end
end
