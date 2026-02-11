defmodule Authify.Tasks.Workers.Scheduled.CleanupExpiredInvitations do
  @moduledoc """
  Scheduled Oban worker that runs daily to cleanup expired invitations.

  This is a thin wrapper that creates and enqueues a task in the Authify
  task framework. The actual cleanup logic lives in the task handler, which
  provides proper state tracking, logging, and error handling.

  Runs daily at 2 AM UTC via Oban Cron.
  """
  use Oban.Worker, queue: :scheduled

  require Logger

  alias Authify.Tasks

  @impl Oban.Worker
  def perform(%Oban.Job{}) do
    Logger.info("Scheduled job triggered: cleanup_expired_invitations")

    # Create and enqueue a task in our task framework
    case Tasks.create_and_enqueue_task(%{
           type: "cleanup_expired_invitations",
           action: "execute",
           organization_id: nil,
           # Global maintenance task
           status: :pending,
           metadata: %{
             scheduled_by: "oban_cron",
             scheduled_at: DateTime.utc_now()
           }
         }) do
      {:ok, task} ->
        Logger.info("Created and enqueued cleanup task #{task.id}")
        :ok

      {:error, changeset} ->
        Logger.error("Failed to create cleanup task: #{inspect(changeset.errors)}")
        {:error, "Failed to create task"}
    end
  end
end
