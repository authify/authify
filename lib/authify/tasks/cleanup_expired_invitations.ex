defmodule Authify.Tasks.CleanupExpiredInvitations do
  @moduledoc """
  Maintenance task that removes old expired invitations from the database.

  This task:
  - Finds all invitations where accepted_at is NULL and expires_at is more than 48 hours in the past
  - Deletes them from the database
  - Logs the count of deleted records

  The 48-hour grace period keeps recently expired invitations around for troubleshooting.

  Typically triggered daily at 2 AM UTC via the scheduled Oban worker.
  """
  use Authify.Tasks.BasicTask

  require Logger

  alias Authify.Accounts.Invitation
  alias Authify.Repo

  import Ecto.Query

  @impl true
  def execute(_task) do
    Logger.info("Starting cleanup of expired invitations")

    # Delete invitations that expired more than 48 hours ago
    cutoff = DateTime.utc_now() |> DateTime.add(-48, :hour)

    deleted_count =
      from(i in Invitation,
        where: is_nil(i.accepted_at),
        where: i.expires_at < ^cutoff
      )
      |> Repo.delete_all()
      |> elem(0)

    Logger.info("Cleaned up #{deleted_count} expired invitation(s) (older than 48 hours)")

    {:ok, %{deleted_count: deleted_count, cutoff: cutoff, completed_at: DateTime.utc_now()}}
  end

  @impl true
  def comparable_tasks(task) do
    # This is a global maintenance task (organization_id is nil)
    # Override the default to handle nil comparison properly
    non_terminal = Task.non_terminal_states()

    from(t in Task,
      where: t.type == ^task.type,
      where: t.action == ^task.action,
      where: is_nil(t.organization_id),
      where: t.status in ^non_terminal,
      where: t.id != ^task.id
    )
  end

  @impl true
  def as_comparable_task(_task) do
    # Only allow one cleanup task to run at a time
    # Multiple concurrent cleanups would be wasteful
    "cleanup_expired_invitations:singleton"
  end

  @impl true
  def on_duplicate(_existing_task, _current_task) do
    # If one is already scheduled/running, skip this one
    :skip
  end
end
