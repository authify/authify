defmodule Authify.Tasks.WaitTaskTest do
  use Authify.DataCase, async: false
  use Oban.Testing, repo: Authify.Repo

  alias Authify.Tasks
  alias Authify.Tasks.WaitTask
  alias Authify.Tasks.Workers.TaskExecutor

  import Authify.AccountsFixtures

  setup do
    org = organization_fixture()
    %{org: org}
  end

  defp insert_task(org, attrs) do
    default = %{
      type: "test_wait_always_met",
      action: "execute",
      organization_id: org.id,
      params: %{}
    }

    {:ok, task} = Tasks.create_task(Map.merge(default, attrs))
    task
  end

  defp perform_task(task) do
    TaskExecutor.perform(%Oban.Job{args: %{"task_id" => task.id}})
  end

  # --- execute_wait/2 unit tests ---

  describe "execute_wait/2 - condition met" do
    test "returns {:ok, results} when check_condition returns {:met, results}", %{org: org} do
      task = insert_task(org, %{type: "test_wait_always_met", status: :running})

      assert {:ok, %{"condition" => "satisfied"}} =
               WaitTask.execute_wait(task, Authify.Tasks.TestWaitAlwaysMet)
    end
  end

  describe "execute_wait/2 - condition not met" do
    test "returns {:wait, :not_met} when condition is not met", %{org: org} do
      Oban.Testing.with_testing_mode(:manual, fn ->
        task = insert_task(org, %{type: "test_wait_never_met", status: :running})

        assert {:wait, :not_met} =
                 WaitTask.execute_wait(task, Authify.Tasks.TestWaitNeverMet)
      end)
    end

    test "transitions task to waiting state", %{org: org} do
      Oban.Testing.with_testing_mode(:manual, fn ->
        task = insert_task(org, %{type: "test_wait_never_met", status: :running})

        WaitTask.execute_wait(task, Authify.Tasks.TestWaitNeverMet)

        updated = Tasks.get_task!(task.id)
        assert updated.status == :waiting
      end)
    end

    test "sets expires_at on first wait", %{org: org} do
      Oban.Testing.with_testing_mode(:manual, fn ->
        task = insert_task(org, %{type: "test_wait_never_met", status: :running})
        assert task.expires_at == nil

        WaitTask.execute_wait(task, Authify.Tasks.TestWaitNeverMet)

        updated = Tasks.get_task!(task.id)
        assert updated.expires_at != nil

        # WaitNeverMet has task_expiration of 60 seconds
        expected_min = DateTime.add(DateTime.utc_now(), 55, :second)
        expected_max = DateTime.add(DateTime.utc_now(), 65, :second)
        assert DateTime.compare(updated.expires_at, expected_min) != :lt
        assert DateTime.compare(updated.expires_at, expected_max) != :gt
      end)
    end

    test "does not overwrite expires_at on subsequent waits", %{org: org} do
      Oban.Testing.with_testing_mode(:manual, fn ->
        original_expires =
          DateTime.add(DateTime.utc_now(), 3600, :second) |> DateTime.truncate(:second)

        task =
          insert_task(org, %{
            type: "test_wait_never_met",
            status: :running,
            expires_at: original_expires
          })

        WaitTask.execute_wait(task, Authify.Tasks.TestWaitNeverMet)

        updated = Tasks.get_task!(task.id)
        assert DateTime.compare(updated.expires_at, original_expires) == :eq
      end)
    end

    test "schedules re-check after task_check_interval", %{org: org} do
      Oban.Testing.with_testing_mode(:manual, fn ->
        task = insert_task(org, %{type: "test_wait_never_met", status: :running})

        WaitTask.execute_wait(task, Authify.Tasks.TestWaitNeverMet)

        # WaitNeverMet has task_check_interval of 5 seconds
        assert_enqueued(worker: TaskExecutor, args: %{"task_id" => task.id})
      end)
    end
  end

  describe "execute_wait/2 - expiration" do
    test "returns {:wait, :expired} when task has expired", %{org: org} do
      past = DateTime.add(DateTime.utc_now(), -10, :second) |> DateTime.truncate(:second)

      task =
        insert_task(org, %{
          type: "test_wait_with_expiration",
          status: :running,
          expires_at: past
        })

      assert {:wait, :expired} =
               WaitTask.execute_wait(task, Authify.Tasks.TestWaitWithExpiration)
    end

    test "transitions expired task through expiring to expired", %{org: org} do
      past = DateTime.add(DateTime.utc_now(), -10, :second) |> DateTime.truncate(:second)

      task =
        insert_task(org, %{
          type: "test_wait_with_expiration",
          status: :running,
          expires_at: past
        })

      WaitTask.execute_wait(task, Authify.Tasks.TestWaitWithExpiration)

      updated = Tasks.get_task!(task.id)
      assert updated.status == :expired
    end

    test "calls on_expiration hook when task expires", %{org: org} do
      past = DateTime.add(DateTime.utc_now(), -10, :second) |> DateTime.truncate(:second)

      task =
        insert_task(org, %{
          type: "test_wait_with_expiration",
          status: :running,
          expires_at: past
        })

      WaitTask.execute_wait(task, Authify.Tasks.TestWaitWithExpiration)

      assert_received {:on_expiration_called, task_id}
      assert task_id == task.id
    end

    test "schedules follow-up task on expiration", %{org: org} do
      past = DateTime.add(DateTime.utc_now(), -10, :second) |> DateTime.truncate(:second)

      task =
        insert_task(org, %{
          type: "test_wait_with_follow_up",
          status: :running,
          expires_at: past
        })

      WaitTask.execute_wait(task, Authify.Tasks.TestWaitWithFollowUp)

      follow_ups = Tasks.list_children(task)

      assert length(follow_ups) == 1
      follow_up = hd(follow_ups)
      assert follow_up.type == "test_succeed"
      assert follow_up.action == "execute"
      assert follow_up.params == %{"reminder" => true}
      assert follow_up.organization_id == task.organization_id
    end

    test "does not check condition when already expired", %{org: org} do
      past = DateTime.add(DateTime.utc_now(), -10, :second) |> DateTime.truncate(:second)

      task =
        insert_task(org, %{
          type: "test_wait_with_expiration",
          status: :running,
          expires_at: past
        })

      WaitTask.execute_wait(task, Authify.Tasks.TestWaitWithExpiration)

      updated = Tasks.get_task!(task.id)
      # If condition was checked and returned :not_met, status would be :waiting
      # Since expiration runs first, status should be :expired
      assert updated.status == :expired
    end
  end

  # --- End-to-end through TaskExecutor ---

  describe "end-to-end via TaskExecutor" do
    test "condition met: task completes through full lifecycle", %{org: org} do
      task = insert_task(org, %{type: "test_wait_always_met"})

      assert :ok = perform_task(task)

      completed = Tasks.get_task!(task.id)
      assert completed.status == :completed
      assert completed.results == %{"condition" => "satisfied"}
      assert completed.started_at != nil
      assert completed.completed_at != nil
    end

    test "condition not met: task transitions to waiting", %{org: org} do
      Oban.Testing.with_testing_mode(:manual, fn ->
        task = insert_task(org, %{type: "test_wait_never_met"})

        assert :ok = perform_task(task)

        waiting = Tasks.get_task!(task.id)
        assert waiting.status == :waiting
        assert waiting.expires_at != nil
        assert waiting.started_at != nil
      end)
    end

    test "expired task transitions to expired via TaskExecutor", %{org: org} do
      past = DateTime.add(DateTime.utc_now(), -10, :second) |> DateTime.truncate(:second)

      task =
        insert_task(org, %{
          type: "test_wait_with_expiration",
          expires_at: past
        })

      assert :ok = perform_task(task)

      expired = Tasks.get_task!(task.id)
      assert expired.status == :expired
    end

    test "waiting task re-executes on next perform cycle when condition met", %{org: org} do
      # Simulate: first cycle put task in waiting, second cycle condition is met
      task = insert_task(org, %{type: "test_wait_always_met"})

      # Manually put in waiting state to simulate prior not-met cycle
      {:ok, running} = Tasks.transition_task(task, :running)
      {:ok, waiting} = Tasks.transition_task(running, :waiting)

      # Second cycle: condition met → completed
      assert :ok = perform_task(waiting)

      completed = Tasks.get_task!(task.id)
      assert completed.status == :completed
      assert completed.results == %{"condition" => "satisfied"}
    end
  end

  # --- Default callback tests ---

  describe "default callbacks" do
    test "task_expiration defaults to 86400 seconds (1 day)" do
      assert Authify.Tasks.TestWaitDefaults.task_expiration() == 86_400
    end

    test "task_check_interval defaults to 60 seconds" do
      assert Authify.Tasks.TestWaitDefaults.task_check_interval() == 60
    end

    test "on_expiration defaults to :ok" do
      assert Authify.Tasks.TestWaitDefaults.on_expiration(%Authify.Tasks.Task{}) == :ok
    end
  end
end
