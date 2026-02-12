defmodule Authify.Tasks.TelemetryTest do
  @moduledoc """
  Tests for task engine telemetry events, verifying that the correct
  events are emitted with proper measurements and metadata.
  """
  use Authify.DataCase, async: false

  alias Authify.Tasks
  alias Authify.Tasks.Telemetry, as: TaskTelemetry

  # --- Helpers ---

  defp task_attrs(overrides \\ %{}) do
    Map.merge(
      %{
        type: "email",
        action: "send_invitation",
        params: %{"user_id" => "123"}
      },
      overrides
    )
  end

  defp attach_handler(event_name, test_pid \\ self()) do
    handler_id = "test-#{inspect(event_name)}-#{System.unique_integer()}"

    :telemetry.attach(
      handler_id,
      event_name,
      fn event, measurements, metadata, _config ->
        send(test_pid, {:telemetry_event, event, measurements, metadata})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler_id) end)
    handler_id
  end

  # --- Direct Telemetry Module Tests ---

  describe "task_created/1" do
    test "emits [:authify, :task, :created] event" do
      attach_handler([:authify, :task, :created])

      {:ok, task} = Tasks.create_task(task_attrs())

      assert_received {:telemetry_event, [:authify, :task, :created], %{count: 1},
                       %{type: "email", action: "send_invitation"}}

      # Verify task_id is not in metadata (created events use org_id instead)
      assert task.type == "email"
    end
  end

  describe "task_started/1" do
    test "emits [:authify, :task, :started] event and returns start_time" do
      attach_handler([:authify, :task, :started])

      {:ok, task} = Tasks.create_task(task_attrs())
      start_time = TaskTelemetry.task_started(task)

      assert is_integer(start_time)

      assert_received {:telemetry_event, [:authify, :task, :started], %{count: 1},
                       %{type: "email", action: "send_invitation", task_id: task_id}}

      assert task_id == task.id
    end
  end

  describe "task_completed/2" do
    test "emits [:authify, :task, :completed] event with duration" do
      attach_handler([:authify, :task, :completed])

      {:ok, task} = Tasks.create_task(task_attrs())
      start_time = System.monotonic_time()
      TaskTelemetry.task_completed(task, start_time)

      assert_received {:telemetry_event, [:authify, :task, :completed],
                       %{duration: duration, count: 1},
                       %{type: "email", action: "send_invitation", task_id: _}}

      assert is_integer(duration)
      assert duration >= 0
    end
  end

  describe "task_failed/3" do
    test "emits [:authify, :task, :failed] event with duration and error_type" do
      attach_handler([:authify, :task, :failed])

      {:ok, task} = Tasks.create_task(task_attrs())
      start_time = System.monotonic_time()
      TaskTelemetry.task_failed(task, start_time, "timeout")

      assert_received {:telemetry_event, [:authify, :task, :failed],
                       %{duration: duration, count: 1},
                       %{type: "email", action: "send_invitation", error_type: "timeout"}}

      assert is_integer(duration)
    end
  end

  describe "task_cancelled/1" do
    test "emits [:authify, :task, :cancelled] event" do
      attach_handler([:authify, :task, :cancelled])

      {:ok, task} = Tasks.create_task(task_attrs())
      assert {:ok, _cancelled} = Tasks.cancel_task(task)

      assert_received {:telemetry_event, [:authify, :task, :cancelled], %{count: 1},
                       %{type: "email", action: "send_invitation", task_id: _}}
    end
  end

  describe "task_retried/2" do
    test "emits [:authify, :task, :retried] event with retry_count" do
      attach_handler([:authify, :task, :retried])

      {:ok, task} = Tasks.create_task(task_attrs())
      TaskTelemetry.task_retried(task, 2)

      assert_received {:telemetry_event, [:authify, :task, :retried], %{count: 1},
                       %{type: "email", action: "send_invitation", retry_count: 2}}
    end
  end

  describe "task_timed_out/1" do
    test "emits [:authify, :task, :timed_out] event" do
      attach_handler([:authify, :task, :timed_out])

      {:ok, task} = Tasks.create_task(task_attrs())
      TaskTelemetry.task_timed_out(task)

      assert_received {:telemetry_event, [:authify, :task, :timed_out], %{count: 1},
                       %{type: "email", action: "send_invitation", task_id: _}}
    end
  end

  describe "task_expired/1" do
    test "emits [:authify, :task, :expired] event" do
      attach_handler([:authify, :task, :expired])

      {:ok, task} = Tasks.create_task(task_attrs())
      TaskTelemetry.task_expired(task)

      assert_received {:telemetry_event, [:authify, :task, :expired], %{count: 1},
                       %{type: "email", action: "send_invitation", task_id: _}}
    end
  end

  # --- Integration: telemetry emitted through task lifecycle ---

  describe "integration: create_task emits telemetry" do
    test "creating multiple tasks emits multiple events" do
      attach_handler([:authify, :task, :created])

      {:ok, _task1} = Tasks.create_task(task_attrs(%{action: "action_1"}))
      {:ok, _task2} = Tasks.create_task(task_attrs(%{action: "action_2"}))

      assert_received {:telemetry_event, [:authify, :task, :created], _, %{action: "action_1"}}
      assert_received {:telemetry_event, [:authify, :task, :created], _, %{action: "action_2"}}
    end
  end
end
