defmodule Authify.Tasks.BasicTaskTest do
  use Authify.DataCase, async: false

  alias Authify.Tasks.BasicTask

  describe "handler_module/1" do
    test "resolves regular task module from type" do
      task = %Authify.Tasks.Task{type: "test_succeed", action: "execute"}
      assert BasicTask.handler_module(task) == Authify.Tasks.TestSucceed
    end

    test "resolves module with underscored type names" do
      task = %Authify.Tasks.Task{type: "test_skip_duplicates", action: "execute"}
      assert BasicTask.handler_module(task) == Authify.Tasks.TestSkipDuplicates
    end

    test "resolves event handler module from event type" do
      assert BasicTask.handler_module("event", "test_event") ==
               Authify.Tasks.Event.TestEvent
    end

    test "returns nil for non-existent handler modules" do
      task = %Authify.Tasks.Task{type: "nonexistent", action: "execute"}
      assert BasicTask.handler_module(task) == nil
    end
  end

  describe "backoff_delay/2" do
    test "exponential backoff" do
      assert BasicTask.backoff_delay(0, :exponential) == 1
      assert BasicTask.backoff_delay(1, :exponential) == 2
      assert BasicTask.backoff_delay(2, :exponential) == 4
      assert BasicTask.backoff_delay(3, :exponential) == 8
      assert BasicTask.backoff_delay(4, :exponential) == 16
    end

    test "linear backoff" do
      assert BasicTask.backoff_delay(1, :linear) == 60
      assert BasicTask.backoff_delay(2, :linear) == 120
      assert BasicTask.backoff_delay(3, :linear) == 180
    end

    test "fibonacci backoff" do
      assert BasicTask.backoff_delay(0, :fibonacci) == 1
      assert BasicTask.backoff_delay(1, :fibonacci) == 1
      assert BasicTask.backoff_delay(2, :fibonacci) == 2
      assert BasicTask.backoff_delay(3, :fibonacci) == 3
      assert BasicTask.backoff_delay(4, :fibonacci) == 5
      assert BasicTask.backoff_delay(5, :fibonacci) == 8
    end

    test "defaults to exponential" do
      assert BasicTask.backoff_delay(3) == 8
    end
  end

  describe "default implementations via use" do
    test "test task provides default callback implementations" do
      handler = Authify.Tasks.TestSucceed
      task = %Authify.Tasks.Task{type: "test_succeed", action: "execute"}

      assert handler.before_complete(task, %{}) == :ok
      assert handler.before_fail(task, :reason) == :ok
      assert handler.before_retry(task, :reason, 1) == :ok
      assert handler.on_duplicate(task, task) == :wait
      assert handler.on_completing(task, task) == :wait
      assert handler.on_failing(task, task) == :wait
      assert handler.on_expiring(task, task) == :wait
      assert handler.on_cancelling(task, task) == :wait
      assert handler.on_timing_out(task, task) == :wait
      assert handler.on_skipping(task, task) == :wait
      assert handler.max_retries() == 0
      assert handler.retry_strategy() == :exponential
      assert handler.should_retry?(:any_reason) == true
    end

    test "tasks can override defaults" do
      handler = Authify.Tasks.TestRetryableFail

      assert handler.max_retries() == 3
      assert handler.retry_strategy() == :exponential
    end

    test "skip duplicates task overrides on_duplicate" do
      handler = Authify.Tasks.TestSkipDuplicates
      task = %Authify.Tasks.Task{type: "test_skip_duplicates", action: "execute"}

      assert handler.on_duplicate(task, task) == :skip
    end

    test "selective retry task overrides should_retry?" do
      handler = Authify.Tasks.TestSelectiveRetry

      assert handler.should_retry?(%{type: "transient"}) == true
      assert handler.should_retry?(%{type: "permanent"}) == false
    end

    test "comparable_tasks returns an Ecto query" do
      handler = Authify.Tasks.TestSucceed

      task = %Authify.Tasks.Task{
        id: Ecto.UUID.generate(),
        type: "test_succeed",
        action: "execute",
        organization_id: 1
      }

      query = handler.comparable_tasks(task)
      assert %Ecto.Query{} = query
    end

    test "as_comparable_task returns string representation" do
      handler = Authify.Tasks.TestSucceed

      task = %Authify.Tasks.Task{
        type: "test_succeed",
        action: "execute",
        organization_id: 1,
        params: %{"key" => "value"}
      }

      result = handler.as_comparable_task(task)
      assert is_binary(result)
      assert result =~ "test_succeed:execute:1:"
    end

    test "no_exclusivity task returns nil for as_comparable_task" do
      handler = Authify.Tasks.TestNoExclusivity
      task = %Authify.Tasks.Task{type: "test_no_exclusivity", action: "execute"}

      assert handler.as_comparable_task(task) == nil
    end
  end
end
