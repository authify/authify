defmodule Authify.Tasks do
  @moduledoc """
  Context module for task engine CRUD operations. Provides functions
  for creating, querying, and managing tasks and their lifecycle.
  """

  import Ecto.Query, warn: false

  alias Authify.Repo
  alias Authify.Tasks.{StateMachine, Task, TaskLog}
  alias Authify.Tasks.Workers.TaskExecutor

  # --- Task CRUD ---

  @doc """
  Creates a new task with the given attributes.
  Defaults to :pending status if not specified.
  """
  def create_task(attrs \\ %{}) do
    %Task{}
    |> Task.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Creates a new task and immediately enqueues it for execution via Oban.
  This is the primary entry point for scheduling task work.
  """
  def create_and_enqueue_task(attrs) do
    with {:ok, task} <- create_task(attrs) do
      delay =
        if task.status == :scheduled and task.scheduled_at do
          max(0, DateTime.diff(task.scheduled_at, DateTime.utc_now(), :second))
        else
          0
        end

      TaskExecutor.schedule_execution(task, delay)
      {:ok, task}
    end
  end

  @doc """
  Gets a single task by ID. Raises if not found.
  """
  def get_task!(id) do
    Repo.get!(Task, id)
  end

  @doc """
  Gets a single task by ID. Returns nil if not found.
  """
  def get_task(id) do
    Repo.get(Task, id)
  end

  @doc """
  Updates a task with the given attributes.
  """
  def update_task(%Task{} = task, attrs) do
    task
    |> Task.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking task changes.
  """
  def change_task(%Task{} = task, attrs \\ %{}) do
    Task.changeset(task, attrs)
  end

  # --- State Transitions ---

  @doc """
  Transitions a task to a new state, enforcing valid transitions
  via the state machine. Updates relevant timestamps automatically.
  """
  def transition_task(%Task{} = task, to_state) do
    case StateMachine.transition(task, to_state) do
      {:ok, changeset} -> Repo.update(changeset)
      {:error, _reason} = error -> error
    end
  end

  # --- Task Queries ---

  @doc """
  Lists tasks for an organization with optional filtering and pagination.
  Returns `{tasks, total_count}`.
  """
  def list_tasks(organization_id, opts \\ []) do
    page = opts[:page] || 1
    per_page = opts[:per_page] || 25
    offset = (page - 1) * per_page

    base_query =
      Task
      |> where([t], t.organization_id == ^organization_id)

    tasks =
      base_query
      |> apply_task_filters(opts)
      |> order_by([t], desc: t.inserted_at)
      |> limit(^per_page)
      |> offset(^offset)
      |> Repo.all()

    total =
      base_query
      |> apply_task_filters(opts)
      |> Repo.aggregate(:count, :id)

    {tasks, total}
  end

  @doc """
  Lists all children of a parent task.
  """
  def list_children(%Task{id: parent_id}) do
    Task
    |> where([t], t.parent_id == ^parent_id)
    |> order_by([t], asc: t.inserted_at)
    |> Repo.all()
  end

  @doc """
  Lists all tasks sharing a correlation ID for workflow tracing.
  """
  def list_correlated_tasks(correlation_id) when is_binary(correlation_id) do
    Task
    |> where([t], t.correlation_id == ^correlation_id)
    |> order_by([t], asc: t.inserted_at)
    |> Repo.all()
  end

  @doc """
  Lists tasks in non-terminal states that are ready to run (pending or scheduled
  with scheduled_at in the past).
  """
  def list_runnable_tasks(limit \\ 100) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    Task
    |> where([t], t.status == :pending)
    |> or_where([t], t.status == :scheduled and t.scheduled_at <= ^now)
    |> order_by([t], asc: t.priority, asc: t.inserted_at)
    |> limit(^limit)
    |> Repo.all()
  end

  # --- Task Logs ---

  @doc """
  Adds a log entry to a task.
  """
  def create_task_log(%Task{id: task_id}, log_data) when is_binary(log_data) do
    %TaskLog{}
    |> TaskLog.changeset(%{task_id: task_id, log_data: log_data})
    |> Repo.insert()
  end

  @doc """
  Lists logs for a task, ordered by creation time.
  """
  def list_task_logs(%Task{id: task_id}) do
    TaskLog
    |> where([l], l.task_id == ^task_id)
    |> order_by([l], asc: l.inserted_at, asc: l.id)
    |> Repo.all()
  end

  # --- Private Helpers ---

  defp apply_task_filters(query, opts) do
    query
    |> filter_by_status(opts[:status])
    |> filter_by_type(opts[:type])
    |> filter_by_action(opts[:action])
  end

  defp filter_by_status(query, nil), do: query

  defp filter_by_status(query, status) when is_atom(status) do
    where(query, [t], t.status == ^status)
  end

  defp filter_by_status(query, statuses) when is_list(statuses) do
    where(query, [t], t.status in ^statuses)
  end

  defp filter_by_type(query, nil), do: query

  defp filter_by_type(query, type) when is_binary(type) do
    where(query, [t], t.type == ^type)
  end

  defp filter_by_action(query, nil), do: query

  defp filter_by_action(query, action) when is_binary(action) do
    where(query, [t], t.action == ^action)
  end
end
