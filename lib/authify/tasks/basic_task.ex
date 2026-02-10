defmodule Authify.Tasks.BasicTask do
  @moduledoc """
  Foundation behavior that all task handlers implement. Defines callbacks for
  execution, lifecycle hooks, exclusivity checking, and retry configuration.

  ## Usage

      defmodule MyApp.Tasks.Handlers.Email.SendWelcome do
        use Authify.Tasks.BasicTask

        @impl true
        def execute(task) do
          # ... send welcome email
          {:ok, %{sent: true}}
        end
      end

  Using `use Authify.Tasks.BasicTask` automatically sets `@behaviour` and
  provides sensible default implementations for all optional callbacks.
  Implementers only need to override `execute/1` and any callbacks they
  want to customize.
  """

  alias Authify.Tasks.Task

  @type task :: %Task{}
  @type task_params :: map()
  @type results :: map()
  @type reason :: term()

  # --- Core Execution ---

  @doc """
  Executes the task's primary logic. Must return `{:ok, results}` on success
  or `{:error, reason}` on failure.
  """
  @callback execute(task :: task()) :: {:ok, results()} | {:error, reason()}

  # --- Lifecycle Hooks ---

  @doc """
  Called when a task completes successfully (during the completing → completed transition).
  Can return `:ok` for no-op or `{:schedule_task, params}` to create a follow-up task.
  """
  @callback on_success(task :: task(), results :: results()) ::
              :ok | {:schedule_task, task_params()}

  @doc """
  Called when a task fails permanently (during the failing → failed transition).
  Can return `:ok` or `{:schedule_task, params}` to create a compensation task.
  """
  @callback on_failure(task :: task(), reason :: reason()) ::
              :ok | {:schedule_task, task_params()}

  @doc """
  Called when a task is about to be retried. Useful for logging or notifications.
  """
  @callback on_retry(task :: task(), reason :: reason(), retry_count :: non_neg_integer()) :: :ok

  # --- Exclusivity Checking (Two-Phase Approach) ---

  @doc """
  Phase 1: Returns an Ecto query to narrow down candidate duplicates using
  indexed columns. The default filters by type, action, organization_id, and
  non-terminal statuses.
  """
  @callback comparable_tasks(current_task :: task()) :: Ecto.Query.t()

  @doc """
  Phase 2: Returns a string representation of the task for exact matching within
  the candidate set. Returns `nil` to skip exclusivity checking entirely.
  """
  @callback as_comparable_task(task :: task()) :: String.t() | nil

  @doc """
  Called when an active-state duplicate is found. Determines what to do with
  the current task.
  """
  @callback on_duplicate(existing_task :: task(), current_task :: task()) ::
              :skip | :wait | :error | :proceed

  # --- Exclusivity Callbacks for Transitioning States ---

  @callback on_completing(existing_task :: task(), current_task :: task()) ::
              :skip | :wait | :error | :proceed

  @callback on_failing(existing_task :: task(), current_task :: task()) ::
              :skip | :wait | :error | :proceed

  @callback on_expiring(existing_task :: task(), current_task :: task()) ::
              :skip | :wait | :error | :proceed

  @callback on_cancelling(existing_task :: task(), current_task :: task()) ::
              :skip | :wait | :error | :proceed

  @callback on_timing_out(existing_task :: task(), current_task :: task()) ::
              :skip | :wait | :error | :proceed

  @callback on_skipping(existing_task :: task(), current_task :: task()) ::
              :skip | :wait | :error | :proceed

  # --- Retry Configuration ---

  @doc """
  Maximum number of retry attempts. Return 0 to disable retries.
  """
  @callback max_retries() :: non_neg_integer()

  @doc """
  Strategy for calculating backoff delay between retries.
  """
  @callback retry_strategy() :: :exponential | :linear | :fibonacci

  @doc """
  Determines whether a specific failure reason should trigger a retry.
  Only called when retries are enabled (max_retries > 0).
  """
  @callback should_retry?(reason :: reason()) :: boolean()

  # --- Default Implementations ---

  defmacro __using__(_opts) do
    quote do
      @behaviour Authify.Tasks.BasicTask

      import Ecto.Query, warn: false

      alias Authify.Tasks.Task

      @impl true
      def on_success(_task, _results), do: :ok

      @impl true
      def on_failure(_task, _reason), do: :ok

      @impl true
      def on_retry(_task, _reason, _retry_count), do: :ok

      @impl true
      def comparable_tasks(task) do
        non_terminal = Task.non_terminal_states()

        from(t in Task,
          where: t.type == ^task.type,
          where: t.action == ^task.action,
          where: t.organization_id == ^task.organization_id,
          where: t.status in ^non_terminal,
          where: t.id != ^task.id
        )
      end

      @impl true
      def as_comparable_task(task) do
        "#{task.type}:#{task.action}:#{task.organization_id}:#{Jason.encode!(task.params)}"
      end

      @impl true
      def on_duplicate(_existing_task, _current_task), do: :wait

      @impl true
      def on_completing(_existing_task, _current_task), do: :wait

      @impl true
      def on_failing(_existing_task, _current_task), do: :wait

      @impl true
      def on_expiring(_existing_task, _current_task), do: :wait

      @impl true
      def on_cancelling(_existing_task, _current_task), do: :wait

      @impl true
      def on_timing_out(_existing_task, _current_task), do: :wait

      @impl true
      def on_skipping(_existing_task, _current_task), do: :wait

      @impl true
      def max_retries, do: 0

      @impl true
      def retry_strategy, do: :exponential

      @impl true
      def should_retry?(_reason), do: true

      defoverridable on_success: 2,
                     on_failure: 2,
                     on_retry: 3,
                     comparable_tasks: 1,
                     as_comparable_task: 1,
                     on_duplicate: 2,
                     on_completing: 2,
                     on_failing: 2,
                     on_expiring: 2,
                     on_cancelling: 2,
                     on_timing_out: 2,
                     on_skipping: 2,
                     max_retries: 0,
                     retry_strategy: 0,
                     should_retry?: 1
    end
  end

  # --- Shared Utilities ---

  @doc """
  Resolves a task's handler module from its type and action fields.
  The convention is: `Authify.Tasks.Handlers.{Type}.{Action}`

  For example, a task with type "email" and action "send_invitation"
  resolves to `Authify.Tasks.Handlers.Email.SendInvitation`.
  """
  def handler_module(%Task{type: type, action: action}) do
    handler_module(type, action)
  end

  def handler_module(type, action) when is_binary(type) and is_binary(action) do
    type_part = type |> Macro.camelize()
    action_part = action |> Macro.camelize()
    # credo:disable-for-next-line Credo.Check.Warning.UnsafeToAtom
    Module.concat([Authify.Tasks.Handlers, type_part, action_part])
  end

  @doc """
  Calculates the backoff delay in seconds for a given retry count and strategy.

  ## Strategies

    * `:exponential` - `2^retry_count` seconds (1s, 2s, 4s, 8s, 16s, ...)
    * `:linear` - `retry_count * 60` seconds (60s, 120s, 180s, ...)
    * `:fibonacci` - Fibonacci sequence in seconds (1s, 1s, 2s, 3s, 5s, 8s, ...)
  """
  def backoff_delay(retry_count, strategy \\ :exponential)

  def backoff_delay(retry_count, :exponential) do
    Integer.pow(2, retry_count)
  end

  def backoff_delay(retry_count, :linear) do
    retry_count * 60
  end

  def backoff_delay(retry_count, :fibonacci) do
    fibonacci(retry_count)
  end

  defp fibonacci(0), do: 1
  defp fibonacci(1), do: 1

  defp fibonacci(n) when n > 1 do
    Enum.reduce(2..n, {1, 1}, fn _i, {a, b} -> {b, a + b} end)
    |> elem(1)
  end
end
