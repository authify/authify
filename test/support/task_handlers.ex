# Regular test tasks - live at Authify.Tasks.Test*

defmodule Authify.Tasks.TestSucceed do
  @moduledoc """
  Test task that always succeeds. Used in TaskExecutor tests.
  """
  use Authify.Tasks.BasicTask

  @impl true
  def execute(_task) do
    {:ok, %{"result" => "success"}}
  end
end

defmodule Authify.Tasks.TestFail do
  @moduledoc """
  Test task that always fails. Used in TaskExecutor tests.
  """
  use Authify.Tasks.BasicTask

  @impl true
  def execute(_task) do
    {:error, %{type: "test_failure", message: "intentional failure"}}
  end
end

defmodule Authify.Tasks.TestRaise do
  @moduledoc """
  Test task that raises an exception. Used in TaskExecutor tests.
  """
  use Authify.Tasks.BasicTask

  @impl true
  def execute(_task) do
    raise "intentional exception"
  end
end

defmodule Authify.Tasks.TestRetryableFail do
  @moduledoc """
  Test task that fails but supports retries. Used in TaskExecutor tests.
  """
  use Authify.Tasks.BasicTask

  @impl true
  def execute(_task) do
    {:error, %{type: "transient", message: "transient failure"}}
  end

  @impl true
  def max_retries, do: 3

  @impl true
  def retry_strategy, do: :exponential
end

defmodule Authify.Tasks.TestSelectiveRetry do
  @moduledoc """
  Test task that retries only specific errors. Used in TaskExecutor tests.
  """
  use Authify.Tasks.BasicTask

  @impl true
  def execute(_task) do
    {:error, %{type: "permanent", message: "permanent failure"}}
  end

  @impl true
  def max_retries, do: 3

  @impl true
  def should_retry?(%{type: "transient"}), do: true
  def should_retry?(_), do: false
end

defmodule Authify.Tasks.TestWithHooks do
  @moduledoc """
  Test task with lifecycle hooks that schedule follow-up tasks.
  Stores hook calls in the process dictionary for test assertions.
  """
  use Authify.Tasks.BasicTask

  @impl true
  def execute(_task) do
    {:ok, %{"result" => "with_hooks"}}
  end

  @impl true
  def on_success(task, results) do
    send(self(), {:on_success_called, task.id, results})
    :ok
  end

  @impl true
  def on_failure(task, reason) do
    send(self(), {:on_failure_called, task.id, reason})
    :ok
  end

  @impl true
  def on_retry(task, reason, retry_count) do
    send(self(), {:on_retry_called, task.id, reason, retry_count})
    :ok
  end
end

defmodule Authify.Tasks.TestFailWithHooks do
  @moduledoc """
  Test task that fails and has hooks for verification.
  """
  use Authify.Tasks.BasicTask

  @impl true
  def execute(_task) do
    {:error, %{type: "hook_test", message: "failure with hooks"}}
  end

  @impl true
  def on_failure(task, reason) do
    send(self(), {:on_failure_called, task.id, reason})
    :ok
  end
end

defmodule Authify.Tasks.TestSuccessWithFollowUp do
  @moduledoc """
  Test task that succeeds and schedules a follow-up task.
  """
  use Authify.Tasks.BasicTask

  @impl true
  def execute(_task) do
    {:ok, %{"result" => "follow_up_needed"}}
  end

  @impl true
  def on_success(_task, _results) do
    {:schedule_task, %{type: "test_succeed", action: "execute", params: %{"follow_up" => true}}}
  end
end

defmodule Authify.Tasks.TestSlow do
  @moduledoc """
  Test task that takes a long time to execute. Used for timeout tests.
  """
  use Authify.Tasks.BasicTask

  @impl true
  def execute(_task) do
    # Sleep for 3 seconds to trigger timeout tests
    Process.sleep(3000)
    {:ok, %{"result" => "slow_success"}}
  end
end

defmodule Authify.Tasks.TestNoExclusivity do
  @moduledoc """
  Test task with no exclusivity checking.
  """
  use Authify.Tasks.BasicTask

  @impl true
  def execute(_task) do
    {:ok, %{"result" => "no_exclusivity"}}
  end

  @impl true
  def as_comparable_task(_task), do: nil
end

defmodule Authify.Tasks.TestSkipDuplicates do
  @moduledoc """
  Test task that skips when duplicates are found.
  """
  use Authify.Tasks.BasicTask

  @impl true
  def execute(_task) do
    {:ok, %{"result" => "skip_duplicates"}}
  end

  @impl true
  def on_duplicate(_existing, _current), do: :skip
end

# --- WaitTask Test Tasks ---

defmodule Authify.Tasks.TestWaitAlwaysMet do
  @moduledoc """
  WaitTask where the condition is always met.
  """
  use Authify.Tasks.WaitTask

  @impl true
  def check_condition(_task) do
    {:met, %{"condition" => "satisfied"}}
  end

  @impl true
  def task_expiration, do: 3600

  @impl true
  def task_check_interval, do: 10
end

defmodule Authify.Tasks.TestWaitNeverMet do
  @moduledoc """
  WaitTask where the condition is never met.
  Uses a short expiration for testing.
  """
  use Authify.Tasks.WaitTask

  @impl true
  def check_condition(_task) do
    :not_met
  end

  @impl true
  def task_expiration, do: 60

  @impl true
  def task_check_interval, do: 5
end

defmodule Authify.Tasks.TestWaitWithExpiration do
  @moduledoc """
  WaitTask with expiration hook that schedules a follow-up.
  """
  use Authify.Tasks.WaitTask

  @impl true
  def check_condition(_task), do: :not_met

  @impl true
  def task_expiration, do: 1

  @impl true
  def task_check_interval, do: 1

  @impl true
  def on_expiration(task) do
    send(self(), {:on_expiration_called, task.id})
    :ok
  end
end

defmodule Authify.Tasks.TestWaitWithFollowUp do
  @moduledoc """
  WaitTask whose expiration schedules a follow-up task.
  """
  use Authify.Tasks.WaitTask

  @impl true
  def check_condition(_task), do: :not_met

  @impl true
  def task_expiration, do: 1

  @impl true
  def task_check_interval, do: 1

  @impl true
  def on_expiration(_task) do
    {:schedule_task, %{type: "test_succeed", action: "execute", params: %{"reminder" => true}}}
  end
end

defmodule Authify.Tasks.TestWaitDefaults do
  @moduledoc """
  WaitTask that uses all default callbacks.
  Used to verify default values for task_expiration, task_check_interval, etc.
  """
  use Authify.Tasks.WaitTask

  @impl true
  def check_condition(_task), do: :not_met
end

# --- WorkflowTask Test Tasks ---

defmodule Authify.Tasks.TestWorkflowSuccess do
  @moduledoc """
  Workflow with two successful steps that accumulate context.
  """
  use Authify.Tasks.WorkflowTask

  @impl true
  def workflow_steps,
    do: [Authify.Tasks.TestWorkflowStepOne, Authify.Tasks.TestWorkflowStepTwo]
end

defmodule Authify.Tasks.TestWorkflowFailStop do
  @moduledoc """
  Workflow that stops on first step failure (default behavior).
  """
  use Authify.Tasks.WorkflowTask

  @impl true
  def workflow_steps, do: [Authify.Tasks.TestWorkflowFailStep]
end

defmodule Authify.Tasks.TestWorkflowFailContinue do
  @moduledoc """
  Workflow that continues to next step after failure.
  """
  use Authify.Tasks.WorkflowTask

  @impl true
  def workflow_steps,
    do: [
      Authify.Tasks.TestWorkflowFailStep,
      Authify.Tasks.TestWorkflowStepTwo
    ]

  @impl true
  def continue_on_failure?, do: true
end

defmodule Authify.Tasks.TestWorkflowStepOne do
  @moduledoc """
  First workflow step; succeeds and returns a value.
  """
  use Authify.Tasks.BasicTask

  @impl true
  def execute(task) do
    {:ok, Map.merge(task.params || %{}, %{"step_one" => 1})}
  end
end

defmodule Authify.Tasks.TestWorkflowStepTwo do
  @moduledoc """
  Second workflow step; succeeds and echoes accumulated context.
  """
  use Authify.Tasks.BasicTask

  @impl true
  def execute(task) do
    {:ok, Map.merge(task.params || %{}, %{"step_two" => 2})}
  end
end

defmodule Authify.Tasks.TestWorkflowFailStep do
  @moduledoc """
  Workflow step that fails.
  """
  use Authify.Tasks.BasicTask

  @impl true
  def execute(_task) do
    {:error, %{type: "workflow_step_failed", message: "intentional failure"}}
  end
end

# --- Event Handler Test Modules ---
# Event handlers live at Authify.Tasks.Event.*
# Only generic test stubs here; real handlers are in lib/authify/tasks/event/

defmodule Authify.Tasks.Event.TestEvent do
  @moduledoc """
  Generic test event handler for verifying event module resolution.
  """
  use Authify.Tasks.BasicTask

  @impl true
  def execute(task) do
    {:ok, %{event: "test_event", params: task.params}}
  end
end
