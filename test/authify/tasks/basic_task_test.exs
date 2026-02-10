defmodule Authify.Tasks.BasicTaskTest do
  use Authify.DataCase, async: false

  alias Authify.Tasks.BasicTask

  describe "handler_module/1" do
    test "resolves module from type and action" do
      task = %Authify.Tasks.Task{type: "email", action: "send_invitation"}
      assert BasicTask.handler_module(task) == Authify.Tasks.Handlers.Email.SendInvitation
    end

    test "resolves module with underscored names" do
      task = %Authify.Tasks.Task{type: "scim_client", action: "sync_user"}
      assert BasicTask.handler_module(task) == Authify.Tasks.Handlers.ScimClient.SyncUser
    end

    test "resolves module from string arguments" do
      assert BasicTask.handler_module("certificate", "renew_cert") ==
               Authify.Tasks.Handlers.Certificate.RenewCert
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
    test "test handler provides default callback implementations" do
      handler = Authify.Tasks.Handlers.Test.Succeed
      task = %Authify.Tasks.Task{type: "test", action: "succeed"}

      assert handler.on_success(task, %{}) == :ok
      assert handler.on_failure(task, :reason) == :ok
      assert handler.on_retry(task, :reason, 1) == :ok
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

    test "handlers can override defaults" do
      handler = Authify.Tasks.Handlers.Test.RetryableFail

      assert handler.max_retries() == 3
      assert handler.retry_strategy() == :exponential
    end

    test "skip duplicates handler overrides on_duplicate" do
      handler = Authify.Tasks.Handlers.Test.SkipDuplicates
      task = %Authify.Tasks.Task{type: "test", action: "skip_duplicates"}

      assert handler.on_duplicate(task, task) == :skip
    end

    test "selective retry handler overrides should_retry?" do
      handler = Authify.Tasks.Handlers.Test.SelectiveRetry

      assert handler.should_retry?(%{type: "transient"}) == true
      assert handler.should_retry?(%{type: "permanent"}) == false
    end

    test "comparable_tasks returns an Ecto query" do
      handler = Authify.Tasks.Handlers.Test.Succeed

      task = %Authify.Tasks.Task{
        id: Ecto.UUID.generate(),
        type: "test",
        action: "succeed",
        organization_id: 1
      }

      query = handler.comparable_tasks(task)
      assert %Ecto.Query{} = query
    end

    test "as_comparable_task returns string representation" do
      handler = Authify.Tasks.Handlers.Test.Succeed

      task = %Authify.Tasks.Task{
        type: "test",
        action: "succeed",
        organization_id: 1,
        params: %{"key" => "value"}
      }

      result = handler.as_comparable_task(task)
      assert is_binary(result)
      assert result =~ "test:succeed:1:"
    end

    test "no_exclusivity handler returns nil for as_comparable_task" do
      handler = Authify.Tasks.Handlers.Test.NoExclusivity
      task = %Authify.Tasks.Task{type: "test", action: "no_exclusivity"}

      assert handler.as_comparable_task(task) == nil
    end
  end
end
