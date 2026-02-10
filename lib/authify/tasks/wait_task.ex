defmodule Authify.Tasks.WaitTask do
  @moduledoc """
  Behavior for tasks that pause execution until a condition is met.
  Extends `BasicTask` with condition checking, expiration, and periodic
  re-scheduling.

  ## Usage

      defmodule MyApp.Tasks.Handlers.User.VerifyEmail do
        use Authify.Tasks.WaitTask

        @impl true
        def check_condition(task) do
          user = Accounts.get_user!(task.params["user_id"])
          if user.email_verified_at, do: {:met, %{"verified" => true}}, else: :not_met
        end

        @impl true
        def task_expiration, do: 7 * 24 * 3600  # 7 days

        @impl true
        def task_check_interval, do: 300  # 5 minutes
      end

  ## Lifecycle

  1. Task is created and enqueued normally
  2. `execute/1` is called (auto-implemented by `use WaitTask`)
  3. `check_condition/1` is called:
     - If `{:met, results}`: task completes successfully with results
     - If `:not_met`: task transitions to `waiting`, sets `expires_at` (if not set),
       and re-schedules after `task_check_interval()` seconds
  4. On expiration: `on_expiration/1` is called, then task transitions to expired
  """

  alias Authify.Tasks
  alias Authify.Tasks.Task
  alias Authify.Tasks.Workers.TaskExecutor

  @type task :: %Task{}
  @type results :: map()
  @type task_params :: map()

  @doc """
  Checks whether the wait condition has been met.
  Returns `{:met, results}` when the condition is satisfied,
  or `:not_met` when the task should continue waiting.
  """
  @callback check_condition(task :: task()) :: {:met, results()} | :not_met

  @doc """
  Maximum time in seconds before the wait task expires.
  Measured from the task's first execution (when `expires_at` is set).
  """
  @callback task_expiration() :: pos_integer()

  @doc """
  Time in seconds between condition checks while waiting.
  """
  @callback task_check_interval() :: pos_integer()

  @doc """
  Called when a wait task expires (condition never met within expiration window).
  Can return `:ok` or `{:schedule_task, params}` to create a follow-up task.
  """
  @callback on_expiration(task :: task()) :: :ok | {:schedule_task, task_params()}

  defmacro __using__(_opts) do
    quote do
      use Authify.Tasks.BasicTask

      @behaviour Authify.Tasks.WaitTask

      @impl Authify.Tasks.BasicTask
      def execute(task) do
        Authify.Tasks.WaitTask.execute_wait(task, __MODULE__)
      end

      @impl Authify.Tasks.WaitTask
      def task_expiration, do: 86_400

      @impl Authify.Tasks.WaitTask
      def task_check_interval, do: 60

      @impl Authify.Tasks.WaitTask
      def on_expiration(_task), do: :ok

      defoverridable task_expiration: 0,
                     task_check_interval: 0,
                     on_expiration: 1,
                     execute: 1
    end
  end

  @doc false
  def execute_wait(%Task{} = task, handler) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    # Check expiration first
    if expired?(task, now) do
      handle_expiration(task, handler)
    else
      case handler.check_condition(task) do
        {:met, results} ->
          {:ok, results}

        :not_met ->
          handle_not_met(task, handler, now)
      end
    end
  end

  defp expired?(%Task{expires_at: nil}, _now), do: false

  defp expired?(%Task{expires_at: expires_at}, now) do
    DateTime.compare(now, expires_at) != :lt
  end

  defp handle_expiration(%Task{} = task, handler) do
    hook_result = handler.on_expiration(task)

    # Transition: running → waiting → expiring → expired
    # The state machine requires running → waiting before expiring
    with {:ok, task} <- Tasks.transition_task(task, :waiting),
         {:ok, task} <- Tasks.transition_task(task, :expiring) do
      maybe_schedule_follow_up(hook_result, task)
      Tasks.transition_task(task, :expired)
    end

    # Return a special tuple that TaskExecutor recognizes to skip normal completion
    {:wait, :expired}
  end

  defp handle_not_met(%Task{} = task, handler, now) do
    # Set expires_at on first wait if not already set
    task = maybe_set_expiration(task, handler, now)

    # Transition to waiting state
    with {:ok, task} <- Tasks.transition_task(task, :waiting) do
      # Re-schedule check after interval
      TaskExecutor.schedule_execution(task, handler.task_check_interval())
    end

    {:wait, :not_met}
  end

  defp maybe_set_expiration(%Task{expires_at: nil} = task, handler, now) do
    expires_at =
      now
      |> DateTime.add(handler.task_expiration(), :second)
      |> DateTime.truncate(:second)

    case Tasks.update_task(task, %{expires_at: expires_at}) do
      {:ok, updated} -> updated
      {:error, _} -> task
    end
  end

  defp maybe_set_expiration(task, _handler, _now), do: task

  defp maybe_schedule_follow_up({:schedule_task, params}, parent_task) do
    attrs =
      params
      |> Map.put(:parent_id, parent_task.id)
      |> Map.put_new(:organization_id, parent_task.organization_id)
      |> Map.put_new(:correlation_id, parent_task.correlation_id)

    case Tasks.create_and_enqueue_task(attrs) do
      {:ok, _follow_up} -> :ok
      {:error, _err} -> :ok
    end
  end

  defp maybe_schedule_follow_up(:ok, _parent_task), do: :ok
  defp maybe_schedule_follow_up(_, _parent_task), do: :ok
end
