# Scheduled Tasks

This directory contains scheduled Oban workers that run on a cron schedule. These workers are thin wrappers that create and enqueue tasks in the Authify task framework.

## Architecture

```
Oban Cron Plugin → Scheduled Worker → Task Framework → Task Handler
    (timing)         (thin wrapper)    (orchestration)   (execution)
```

### Why This Approach?

This "best of both worlds" pattern provides:
- **Oban Cron** handles reliable scheduling with cron syntax
- **Scheduled Worker** is a thin wrapper (creates + enqueues a task)
- **Task Framework** provides state tracking, logging, retries, exclusivity
- **Task Handler** contains the actual business logic

## Adding a New Scheduled Task

### 1. Add Cron Entry

Edit `config/config.exs` and add your schedule to the Oban crontab:

```elixir
config :authify, Oban,
  # ... other config ...
  plugins: [
    {Oban.Plugins.Cron,
     crontab: [
       # Daily at 2 AM UTC - cleanup expired invitations
       {"0 2 * * *", Authify.Tasks.Workers.Scheduled.CleanupExpiredInvitations},

       # Add your task here:
       {"0 3 * * *", Authify.Tasks.Workers.Scheduled.YourNewTask}
     ]}
  ]
```

**Cron Syntax Reference:**
- `"0 * * * *"` - Every hour
- `"0 2 * * *"` - Daily at 2 AM UTC
- `"0 0 * * 0"` - Weekly on Sunday at midnight
- `"0 0 1 * *"` - Monthly on the 1st at midnight

### 2. Create the Scheduled Worker (Thin Wrapper)

Create `lib/authify/tasks/workers/scheduled/your_new_task.ex`:

```elixir
defmodule Authify.Tasks.Workers.Scheduled.YourNewTask do
  @moduledoc """
  Scheduled Oban worker that runs [WHEN] to [DO WHAT].

  This is a thin wrapper that creates and enqueues a task in the Authify
  task framework. The actual logic lives in the task handler.

  Runs [SCHEDULE] via Oban Cron.
  """
  use Oban.Worker, queue: :scheduled

  require Logger
  alias Authify.Tasks

  @impl Oban.Worker
  def perform(%Oban.Job{}) do
    Logger.info("Scheduled job triggered: your_new_task")

    case Tasks.create_and_enqueue_task(%{
           type: "your_new_task",
           action: "execute",
           organization_id: nil,  # Use nil for global tasks
           status: :pending,
           metadata: %{
             scheduled_by: "oban_cron",
             scheduled_at: DateTime.utc_now()
           }
         }) do
      {:ok, task} ->
        Logger.info("Created and enqueued task #{task.id}")
        :ok

      {:error, changeset} ->
        Logger.error("Failed to create task: #{inspect(changeset.errors)}")
        {:error, "Failed to create task"}
    end
  end
end
```

### 3. Create the Task Handler (Business Logic)

Create `lib/authify/tasks/your_new_task.ex`:

```elixir
defmodule Authify.Tasks.YourNewTask do
  @moduledoc """
  Task handler that [DOES WHAT].

  [More detailed description]
  """
  use Authify.Tasks.BasicTask

  require Logger
  alias Authify.Repo
  import Ecto.Query

  @impl true
  def execute(_task) do
    Logger.info("Starting your_new_task")

    # Your business logic here
    result = do_your_work()

    Logger.info("Completed your_new_task")
    {:ok, %{result: result, completed_at: DateTime.utc_now()}}
  end

  # For global maintenance tasks (organization_id: nil), override comparable_tasks
  @impl true
  def comparable_tasks(task) do
    non_terminal = Task.non_terminal_states()

    from(t in Task,
      where: t.type == ^task.type,
      where: t.action == ^task.action,
      where: is_nil(t.organization_id),  # Important for global tasks!
      where: t.status in ^non_terminal,
      where: t.id != ^task.id
    )
  end

  @impl true
  def as_comparable_task(_task) do
    # Only allow one instance to run at a time
    "your_new_task:singleton"
  end

  @impl true
  def on_duplicate(_existing_task, _current_task) do
    # If one is already scheduled/running, skip this one
    :skip
  end

  defp do_your_work do
    # Your implementation here
  end
end
```

### 4. Write Tests

Create tests for both components:

**Scheduled Worker Test** (`test/authify/tasks/workers/scheduled/your_new_task_test.exs`):

```elixir
defmodule Authify.Tasks.Workers.Scheduled.YourNewTaskTest do
  use Authify.DataCase, async: false
  use Oban.Testing, repo: Authify.Repo

  alias Authify.Tasks
  alias Authify.Tasks.Workers.Scheduled.YourNewTask
  alias Authify.Tasks.Workers.TaskExecutor

  describe "perform/1" do
    test "creates and enqueues a task" do
      Oban.Testing.with_testing_mode(:manual, fn ->
        job = %Oban.Job{args: %{}}

        assert :ok = YourNewTask.perform(job)

        tasks = Tasks.list_all_tasks() |> elem(0)
        task = Enum.find(tasks, &(&1.type == "your_new_task"))

        assert task
        assert task.type == "your_new_task"
        assert task.action == "execute"
        assert_enqueued(worker: TaskExecutor, args: %{"task_id" => task.id})
      end)
    end
  end
end
```

**Task Handler Test** (`test/authify/tasks/your_new_task_test.exs`):

```elixir
defmodule Authify.Tasks.YourNewTaskTest do
  use Authify.DataCase, async: true

  alias Authify.Tasks.YourNewTask

  describe "execute/1" do
    test "performs the expected work" do
      task = %Authify.Tasks.Task{
        type: "your_new_task",
        action: "execute"
      }

      assert {:ok, results} = YourNewTask.execute(task)
      # Add assertions about results
    end
  end
end
```

## Existing Scheduled Tasks

- **CleanupExpiredInvitations** - Runs daily at 2 AM UTC
  - Deletes invitations that expired more than 48 hours ago
  - Keeps recently expired invitations for troubleshooting

## Notes

- **Organization-scoped tasks**: Set `organization_id` to the org ID
- **Global maintenance tasks**: Set `organization_id: nil` and override `comparable_tasks/1`
- **Task exclusivity**: Use `as_comparable_task/1` to prevent duplicate executions
- **Queue selection**: Use `:scheduled` queue for cron-triggered tasks
- **Testing**: Oban runs in `:inline` mode during tests (see `config/test.exs`)