defmodule Authify.Tasks.Workers.TaskExecutor do
  @moduledoc """
  Oban worker that dispatches task execution to the appropriate handler module.

  This worker is the bridge between Oban's job processing and the task engine's
  behavior-based architecture. It:

  1. Loads the task from the database
  2. Resolves the handler module from task type/action
  3. Checks exclusivity (two-phase duplicate detection)
  4. Transitions the task through its lifecycle states
  5. Handles retries, failures, and success hooks

  ## Job Args

  The Oban job receives `%{"task_id" => id}` as its args. All task data is
  loaded fresh from the database to ensure consistency.
  """

  use Oban.Worker, queue: :tasks, max_attempts: 1

  require Logger

  alias Authify.Repo
  alias Authify.Tasks
  alias Authify.Tasks.{BasicTask, ExclusivityLock, Task}

  @active_states Task.active_states()
  @transitioning_states Task.transitioning_states()

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"task_id" => task_id}}) do
    case Tasks.get_task(task_id) do
      nil ->
        Logger.warning("TaskExecutor: task #{task_id} not found, discarding job")
        :ok

      task ->
        execute_task(task)
    end
  end

  # --- Core Execution Flow ---

  defp execute_task(%Task{status: status} = task)
       when status in [:pending, :retrying, :waiting] do
    with {:ok, handler} <- resolve_handler(task),
         {:ok, task} <- check_and_transition_to_running(task, handler) do
      run_task(task, handler)
    else
      {:skip, task} ->
        finalize_skip(task)

      {:wait, task} ->
        schedule_retry(task, 30)

      {:error, :no_handler} ->
        fail_task(task, %{
          type: "handler_not_found",
          message: "No handler module found for #{task.type}/#{task.action}"
        })

      {:error, reason} ->
        fail_task(task, %{type: "transition_error", message: inspect(reason)})
    end
  end

  defp execute_task(%Task{status: status} = task) when status in [:scheduled] do
    # Scheduled tasks that are ready: transition to pending first, then execute
    case Tasks.transition_task(task, :pending) do
      {:ok, task} -> execute_task(task)
      {:error, reason} -> fail_task(task, %{type: "transition_error", message: inspect(reason)})
    end
  end

  defp execute_task(%Task{status: status}) when status in [:running] do
    # Already running (shouldn't happen normally), just return ok to avoid re-processing
    :ok
  end

  defp execute_task(%Task{id: id, status: status}) do
    Logger.warning("TaskExecutor: task #{id} in unexpected state #{status}, skipping")
    :ok
  end

  # --- Handler Resolution ---

  defp resolve_handler(%Task{} = task) do
    case BasicTask.handler_module(task) do
      nil ->
        {:error, :no_handler}

      module ->
        if Code.ensure_loaded?(module) and function_exported?(module, :execute, 1) do
          {:ok, module}
        else
          {:error, :no_handler}
        end
    end
  end

  # --- Exclusivity & Transition to Running ---

  # When a task has an exclusivity key, we use ExclusivityLock to serialize the
  # check and transition. This ensures that only one task with a given
  # exclusivity key can evaluate candidates and transition to :running at a
  # time, eliminating the TOCTOU race where two identical tasks could both see
  # no duplicates and both proceed.
  defp check_and_transition_to_running(%Task{} = task, handler) do
    current_key = handler.as_comparable_task(task)

    if is_nil(current_key) do
      # No exclusivity — transition directly without locking
      case Tasks.transition_task(task, :running) do
        {:ok, task} -> {:ok, task}
        {:error, reason} -> {:error, reason}
      end
    else
      ExclusivityLock.with_lock(current_key, fn ->
        do_exclusivity_check(task, handler)
      end)
    end
  end

  defp do_exclusivity_check(%Task{} = task, handler) do
    case check_exclusivity(task, handler) do
      :proceed ->
        case Tasks.transition_task(task, :running) do
          {:ok, task} -> {:ok, task}
          {:error, reason} -> {:error, reason}
        end

      :skip ->
        {:skip, task}

      :wait ->
        {:wait, task}

      :error ->
        {:error, :duplicate_detected}
    end
  end

  # --- Two-Phase Exclusivity Check ---

  defp check_exclusivity(%Task{} = task, handler) do
    current_key = handler.as_comparable_task(task)
    candidates = handler.comparable_tasks(task) |> Repo.all()

    duplicate =
      Enum.find(candidates, fn candidate ->
        handler.as_comparable_task(candidate) == current_key
      end)

    case duplicate do
      nil ->
        :proceed

      %Task{status: status} when status in @active_states ->
        handler.on_duplicate(duplicate, task)

      %Task{status: :completing} ->
        handler.on_completing(duplicate, task)

      %Task{status: :failing} ->
        handler.on_failing(duplicate, task)

      %Task{status: :expiring} ->
        handler.on_expiring(duplicate, task)

      %Task{status: :cancelling} ->
        handler.on_cancelling(duplicate, task)

      %Task{status: :timing_out} ->
        handler.on_timing_out(duplicate, task)

      %Task{status: :skipping} ->
        handler.on_skipping(duplicate, task)

      %Task{status: status} when status in @transitioning_states ->
        # Catch-all for any new transitioning states
        :wait
    end
  end

  # --- Task Execution ---

  defp run_task(%Task{timeout_seconds: timeout_seconds} = task, handler)
       when is_integer(timeout_seconds) and timeout_seconds > 0 do
    run_task_with_timeout(task, handler, timeout_seconds * 1000)
  end

  defp run_task(%Task{} = task, handler) do
    # No timeout configured, execute directly
    case handler.execute(task) do
      {:ok, results} ->
        handle_success(task, handler, results)

      {:error, reason} ->
        handle_failure(task, handler, reason)

      {:wait, _} ->
        # WaitTask returns this when condition is not met
        # The WaitTask behavior handles its own re-scheduling
        :ok

      other ->
        handle_failure(task, handler, %{type: "unexpected_return", value: inspect(other)})
    end
  rescue
    exception ->
      reason = %{
        type: "exception",
        message: Exception.message(exception),
        stacktrace: Exception.format_stacktrace(__STACKTRACE__)
      }

      handle_failure(task, handler, reason)
  end

  defp handle_result(%Task{} = task, handler, result) do
    case result do
      {:ok, results} ->
        handle_success(task, handler, results)

      {:error, reason} ->
        handle_failure(task, handler, reason)

      {:wait, _} ->
        # WaitTask returns this when condition is not met
        :ok

      other ->
        handle_failure(task, handler, %{type: "unexpected_return", value: inspect(other)})
    end
  end

  # --- Timeout Path ---

  defp run_task_with_timeout(%Task{} = task, handler, timeout_ms) do
    task_ref = make_ref()
    parent = self()

    {pid, monitor_ref} =
      spawn_monitor(fn ->
        result =
          try do
            handler.execute(task)
          rescue
            exception ->
              {:exception, exception, __STACKTRACE__}
          end

        send(parent, {task_ref, :result, result})
      end)

    receive do
      {^task_ref, :result, {:exception, exception, stacktrace}} ->
        reason = %{
          type: "exception",
          message: Exception.message(exception),
          stacktrace: Exception.format_stacktrace(stacktrace)
        }

        handle_failure(task, handler, reason)

      {^task_ref, :result, result} ->
        handle_result(task, handler, result)

      {:DOWN, ^monitor_ref, :process, ^pid, :normal} ->
        :ok

      {:DOWN, ^monitor_ref, :process, ^pid, reason} ->
        handle_failure(task, handler, %{
          type: "process_crash",
          message: "Task process crashed: #{inspect(reason)}"
        })
    after
      timeout_ms ->
        Process.demonitor(monitor_ref, [:flush])
        Process.exit(pid, :kill)
        handle_timeout(task, handler)
    end
  end

  defp handle_timeout(%Task{} = task, _handler) do
    reason = %{
      type: "timeout",
      message: "Task execution exceeded timeout of #{task.timeout_seconds} seconds"
    }

    # Transition: running → timing_out → timed_out
    with {:ok, task} <-
           Tasks.update_task(task, %{
             errors: Map.put(task.errors || %{}, "final", reason)
           }),
         {:ok, task} <- Tasks.transition_task(task, :timing_out),
         {:ok, _task} <- Tasks.transition_task(task, :timed_out) do
      :ok
    else
      {:error, err} ->
        Logger.error("TaskExecutor: failed to timeout task #{task.id}: #{inspect(err)}")
        :ok
    end
  end

  # --- Success Path ---

  defp handle_success(%Task{} = task, handler, results) do
    # Transition: running → completing
    with {:ok, task} <- Tasks.update_task(task, %{results: results}),
         {:ok, task} <- Tasks.transition_task(task, :completing) do
      # Run on_success hook
      hook_result = handler.on_success(task, results)

      # Handle follow-up task from hook
      maybe_schedule_follow_up(hook_result, task)

      # Transition: completing → completed
      Tasks.transition_task(task, :completed)
      :ok
    else
      {:error, reason} ->
        Logger.error("TaskExecutor: failed to complete task #{task.id}: #{inspect(reason)}")
        :ok
    end
  end

  # --- Failure Path ---

  defp handle_failure(%Task{} = task, handler, reason) do
    task = refresh_task(task)

    if should_retry?(task, handler, reason) do
      perform_retry(task, handler, reason)
    else
      perform_final_failure(task, handler, reason)
    end
  end

  defp should_retry?(%Task{} = task, handler, reason) do
    handler.max_retries() > 0 and
      task.retry_count < handler.max_retries() and
      handler.should_retry?(reason)
  end

  defp perform_retry(%Task{} = task, handler, reason) do
    new_retry_count = task.retry_count + 1
    delay = BasicTask.backoff_delay(new_retry_count, handler.retry_strategy())

    # Call on_retry hook
    handler.on_retry(task, reason, new_retry_count)

    scheduled_at =
      DateTime.utc_now()
      |> DateTime.add(delay, :second)
      |> DateTime.truncate(:second)

    # Update task with retry info and transition to retrying
    with {:ok, task} <-
           Tasks.update_task(task, %{
             retry_count: new_retry_count,
             errors:
               Map.put(task.errors || %{}, "attempt_#{new_retry_count}", normalize_reason(reason)),
             scheduled_at: scheduled_at
           }),
         {:ok, task} <- Tasks.transition_task(task, :retrying) do
      # Schedule Oban job for retry
      schedule_execution(task, delay)
      :ok
    else
      {:error, err} ->
        Logger.error(
          "TaskExecutor: failed to schedule retry for task #{task.id}: #{inspect(err)}"
        )

        :ok
    end
  end

  defp perform_final_failure(%Task{} = task, handler, reason) do
    with {:ok, task} <-
           Tasks.update_task(task, %{
             errors: Map.put(task.errors || %{}, "final", normalize_reason(reason))
           }),
         {:ok, task} <- Tasks.transition_task(task, :failing) do
      # Run on_failure hook
      hook_result = handler.on_failure(task, reason)
      maybe_schedule_follow_up(hook_result, task)

      # Transition: failing → failed
      Tasks.transition_task(task, :failed)
      :ok
    else
      {:error, err} ->
        Logger.error(
          "TaskExecutor: failed to finalize failure for task #{task.id}: #{inspect(err)}"
        )

        :ok
    end
  end

  # --- Direct Failure (no handler available) ---

  defp fail_task(%Task{status: :running} = task, reason) do
    with {:ok, task} <-
           Tasks.update_task(task, %{
             errors: Map.put(task.errors || %{}, "final", normalize_reason(reason))
           }),
         {:ok, task} <- Tasks.transition_task(task, :failing),
         {:ok, _task} <- Tasks.transition_task(task, :failed) do
      :ok
    else
      {:error, err} ->
        Logger.error("TaskExecutor: failed to fail task #{task.id}: #{inspect(err)}")
        :ok
    end
  end

  defp fail_task(%Task{} = task, reason) do
    # Task is not yet running (e.g., handler not found before transition to running).
    # Transition to running first so we can follow the normal failure path.
    case Tasks.transition_task(task, :running) do
      {:ok, running_task} ->
        fail_task(running_task, reason)

      {:error, err} ->
        Logger.error("TaskExecutor: failed to fail task #{task.id}: #{inspect(err)}")
        :ok
    end
  end

  # --- Skip Path ---

  defp finalize_skip(%Task{} = task) do
    with {:ok, task} <- Tasks.transition_task(task, :skipping),
         {:ok, _task} <- Tasks.transition_task(task, :skipped) do
      :ok
    else
      {:error, err} ->
        Logger.error("TaskExecutor: failed to skip task #{task.id}: #{inspect(err)}")
        :ok
    end
  end

  # --- Scheduling ---

  @doc """
  Enqueues a task for execution via Oban. Optionally accepts a delay in seconds
  for scheduled/retry execution.
  """
  def schedule_execution(%Task{id: task_id}, delay_seconds \\ 0) do
    job_args = %{"task_id" => task_id}

    if delay_seconds > 0 do
      job_args
      |> __MODULE__.new(schedule_in: delay_seconds)
      |> Oban.insert()
    else
      job_args
      |> __MODULE__.new()
      |> Oban.insert()
    end
  end

  defp schedule_retry(%Task{} = task, delay_seconds) do
    schedule_execution(task, delay_seconds)
    :ok
  end

  # --- Helpers ---

  defp refresh_task(%Task{id: id}), do: Tasks.get_task!(id)

  defp normalize_reason(reason) when is_map(reason), do: reason
  defp normalize_reason(reason) when is_binary(reason), do: %{"message" => reason}
  defp normalize_reason(reason), do: %{"message" => inspect(reason)}

  defp maybe_schedule_follow_up({:schedule_task, params}, parent_task) do
    attrs =
      params
      |> Map.put(:parent_id, parent_task.id)
      |> Map.put_new(:organization_id, parent_task.organization_id)
      |> Map.put_new(:correlation_id, parent_task.correlation_id)

    case Tasks.create_task(attrs) do
      {:ok, follow_up} ->
        schedule_execution(follow_up)

      {:error, err} ->
        Logger.error("TaskExecutor: failed to create follow-up task: #{inspect(err)}")
    end
  end

  defp maybe_schedule_follow_up(:ok, _parent_task), do: :ok
  defp maybe_schedule_follow_up(_, _parent_task), do: :ok
end
