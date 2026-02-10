defmodule Authify.Tasks.Handlers.Test.Succeed do
  @moduledoc """
  Test handler that always succeeds. Used in TaskExecutor tests.
  """
  use Authify.Tasks.BasicTask

  @impl true
  def execute(_task) do
    {:ok, %{"result" => "success"}}
  end
end

defmodule Authify.Tasks.Handlers.Test.Fail do
  @moduledoc """
  Test handler that always fails. Used in TaskExecutor tests.
  """
  use Authify.Tasks.BasicTask

  @impl true
  def execute(_task) do
    {:error, %{type: "test_failure", message: "intentional failure"}}
  end
end

defmodule Authify.Tasks.Handlers.Test.Raise do
  @moduledoc """
  Test handler that raises an exception. Used in TaskExecutor tests.
  """
  use Authify.Tasks.BasicTask

  @impl true
  def execute(_task) do
    raise "intentional exception"
  end
end

defmodule Authify.Tasks.Handlers.Test.RetryableFail do
  @moduledoc """
  Test handler that fails but supports retries. Used in TaskExecutor tests.
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

defmodule Authify.Tasks.Handlers.Test.SelectiveRetry do
  @moduledoc """
  Test handler that retries only specific errors. Used in TaskExecutor tests.
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

defmodule Authify.Tasks.Handlers.Test.WithHooks do
  @moduledoc """
  Test handler with lifecycle hooks that schedule follow-up tasks.
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

defmodule Authify.Tasks.Handlers.Test.FailWithHooks do
  @moduledoc """
  Test handler that fails and has hooks for verification.
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

defmodule Authify.Tasks.Handlers.Test.SuccessWithFollowUp do
  @moduledoc """
  Test handler that succeeds and schedules a follow-up task.
  """
  use Authify.Tasks.BasicTask

  @impl true
  def execute(_task) do
    {:ok, %{"result" => "follow_up_needed"}}
  end

  @impl true
  def on_success(_task, _results) do
    {:schedule_task, %{type: "test", action: "succeed", params: %{"follow_up" => true}}}
  end
end

defmodule Authify.Tasks.Handlers.Test.NoExclusivity do
  @moduledoc """
  Test handler with no exclusivity checking.
  """
  use Authify.Tasks.BasicTask

  @impl true
  def execute(_task) do
    {:ok, %{"result" => "no_exclusivity"}}
  end

  @impl true
  def as_comparable_task(_task), do: nil
end

defmodule Authify.Tasks.Handlers.Test.SkipDuplicates do
  @moduledoc """
  Test handler that skips when duplicates are found.
  """
  use Authify.Tasks.BasicTask

  @impl true
  def execute(_task) do
    {:ok, %{"result" => "skip_duplicates"}}
  end

  @impl true
  def on_duplicate(_existing, _current), do: :skip
end

# --- WaitTask Test Handlers ---

defmodule Authify.Tasks.Handlers.Test.WaitAlwaysMet do
  @moduledoc """
  WaitTask handler where the condition is always met.
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

defmodule Authify.Tasks.Handlers.Test.WaitNeverMet do
  @moduledoc """
  WaitTask handler where the condition is never met.
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

defmodule Authify.Tasks.Handlers.Test.WaitWithExpiration do
  @moduledoc """
  WaitTask handler with expiration hook that schedules a follow-up.
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

defmodule Authify.Tasks.Handlers.Test.WaitWithFollowUp do
  @moduledoc """
  WaitTask handler whose expiration schedules a follow-up task.
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
    {:schedule_task, %{type: "test", action: "succeed", params: %{"reminder" => true}}}
  end
end
