defmodule Authify.Tasks.Telemetry do
  @moduledoc """
  Telemetry event emitters for the task engine. Provides convenience functions
  that call `:telemetry.execute/3` with consistent event names and metadata.

  ## Event Naming Convention

  All events follow the pattern `[:authify, :task, :action]`:

  - `[:authify, :task, :created]` — Task created
  - `[:authify, :task, :started]` — Task execution started
  - `[:authify, :task, :completed]` — Task completed successfully
  - `[:authify, :task, :failed]` — Task failed permanently
  - `[:authify, :task, :cancelled]` — Task cancelled
  - `[:authify, :task, :retried]` — Task scheduled for retry
  - `[:authify, :task, :timed_out]` — Task exceeded timeout
  - `[:authify, :task, :expired]` — WaitTask expired
  """

  alias Authify.Tasks.Task

  @doc """
  Emits a task created event.
  """
  def task_created(%Task{} = task) do
    :telemetry.execute(
      [:authify, :task, :created],
      %{count: 1},
      %{type: task.type, action: task.action, organization_id: task.organization_id}
    )
  end

  @doc """
  Emits a task started event. Returns the monotonic start time for duration tracking.
  """
  def task_started(%Task{} = task) do
    start_time = System.monotonic_time()

    :telemetry.execute(
      [:authify, :task, :started],
      %{count: 1},
      %{type: task.type, action: task.action, task_id: task.id}
    )

    start_time
  end

  @doc """
  Emits a task completed event with duration.
  """
  def task_completed(%Task{} = task, start_time) do
    duration = System.monotonic_time() - start_time

    :telemetry.execute(
      [:authify, :task, :completed],
      %{duration: duration, count: 1},
      %{type: task.type, action: task.action, task_id: task.id}
    )
  end

  @doc """
  Emits a task failed event with duration.
  """
  def task_failed(%Task{} = task, start_time, error_type \\ "unknown") do
    duration = System.monotonic_time() - start_time

    :telemetry.execute(
      [:authify, :task, :failed],
      %{duration: duration, count: 1},
      %{type: task.type, action: task.action, task_id: task.id, error_type: error_type}
    )
  end

  @doc """
  Emits a task cancelled event.
  """
  def task_cancelled(%Task{} = task) do
    :telemetry.execute(
      [:authify, :task, :cancelled],
      %{count: 1},
      %{type: task.type, action: task.action, task_id: task.id}
    )
  end

  @doc """
  Emits a task retried event.
  """
  def task_retried(%Task{} = task, retry_count) do
    :telemetry.execute(
      [:authify, :task, :retried],
      %{count: 1},
      %{type: task.type, action: task.action, task_id: task.id, retry_count: retry_count}
    )
  end

  @doc """
  Emits a task timed out event.
  """
  def task_timed_out(%Task{} = task) do
    :telemetry.execute(
      [:authify, :task, :timed_out],
      %{count: 1},
      %{type: task.type, action: task.action, task_id: task.id}
    )
  end

  @doc """
  Emits a task expired event (WaitTask expiration).
  """
  def task_expired(%Task{} = task) do
    :telemetry.execute(
      [:authify, :task, :expired],
      %{count: 1},
      %{type: task.type, action: task.action, task_id: task.id}
    )
  end
end
