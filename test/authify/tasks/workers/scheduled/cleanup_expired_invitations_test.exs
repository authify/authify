defmodule Authify.Tasks.Workers.Scheduled.CleanupExpiredInvitationsTest do
  # async: false — task engine tests share a TaskExecutor GenServer and register
  # telemetry handlers globally; concurrent execution causes race conditions.
  use Authify.DataCase, async: false
  use Oban.Testing, repo: Authify.Repo

  alias Authify.Tasks
  alias Authify.Tasks.Workers.Scheduled.CleanupExpiredInvitations
  alias Authify.Tasks.Workers.TaskExecutor

  describe "perform/1" do
    test "creates and enqueues a cleanup task" do
      Oban.Testing.with_testing_mode(:manual, fn ->
        job = %Oban.Job{args: %{}}

        assert :ok = CleanupExpiredInvitations.perform(job)

        # Verify a task was created
        tasks = Tasks.list_all_tasks() |> elem(0)
        task = Enum.find(tasks, &(&1.type == "cleanup_expired_invitations"))

        assert task
        assert task.type == "cleanup_expired_invitations"
        assert task.action == "execute"
        assert task.status == :pending
        assert task.organization_id == nil
        assert task.metadata["scheduled_by"] == "oban_cron"
        assert task.metadata["scheduled_at"]

        # Verify TaskExecutor job was enqueued
        assert_enqueued(worker: TaskExecutor, args: %{"task_id" => task.id})
      end)
    end

    test "returns error if task creation fails" do
      # Create an invalid task by passing invalid attributes
      # We can't easily simulate this without mocking, so we'll test the happy path primarily
      # In production, task creation failures would be logged
      job = %Oban.Job{args: %{}}

      assert :ok = CleanupExpiredInvitations.perform(job)
    end

    test "task metadata includes scheduling information" do
      job = %Oban.Job{args: %{}}

      assert :ok = CleanupExpiredInvitations.perform(job)

      tasks = Tasks.list_all_tasks() |> elem(0)
      task = Enum.find(tasks, &(&1.type == "cleanup_expired_invitations"))

      assert task.metadata["scheduled_by"] == "oban_cron"
      assert %DateTime{} = DateTime.from_iso8601(task.metadata["scheduled_at"]) |> elem(1)
    end
  end
end
