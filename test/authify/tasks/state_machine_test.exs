defmodule Authify.Tasks.StateMachineTest do
  @moduledoc """
  Tests for the task state machine, ensuring valid transitions
  are allowed and invalid transitions are rejected.
  """
  use Authify.DataCase, async: true

  alias Authify.Tasks.{StateMachine, Task}

  describe "valid_transition?/2" do
    test "allows active state → transitioning state transitions" do
      assert StateMachine.valid_transition?(:scheduled, :pending)
      assert StateMachine.valid_transition?(:scheduled, :running)
      assert StateMachine.valid_transition?(:pending, :running)
      assert StateMachine.valid_transition?(:running, :completing)
      assert StateMachine.valid_transition?(:running, :failing)
      assert StateMachine.valid_transition?(:running, :retrying)
      assert StateMachine.valid_transition?(:running, :waiting)
      assert StateMachine.valid_transition?(:running, :timing_out)
    end

    test "allows transitioning → terminal state transitions" do
      assert StateMachine.valid_transition?(:completing, :completed)
      assert StateMachine.valid_transition?(:failing, :failed)
      assert StateMachine.valid_transition?(:expiring, :expired)
      assert StateMachine.valid_transition?(:cancelling, :cancelled)
      assert StateMachine.valid_transition?(:timing_out, :timed_out)
      assert StateMachine.valid_transition?(:skipping, :skipped)
    end

    test "allows cancellation from cancellable states" do
      assert StateMachine.valid_transition?(:scheduled, :cancelling)
      assert StateMachine.valid_transition?(:pending, :cancelling)
      assert StateMachine.valid_transition?(:running, :cancelling)
      assert StateMachine.valid_transition?(:retrying, :cancelling)
      assert StateMachine.valid_transition?(:waiting, :cancelling)
    end

    test "allows retry-related transitions" do
      assert StateMachine.valid_transition?(:retrying, :running)
      assert StateMachine.valid_transition?(:retrying, :failing)
    end

    test "allows wait-related transitions" do
      assert StateMachine.valid_transition?(:waiting, :running)
      assert StateMachine.valid_transition?(:waiting, :expiring)
    end

    test "allows duplicate detection transition" do
      assert StateMachine.valid_transition?(:pending, :skipping)
    end

    test "rejects terminal state transitions" do
      for terminal_state <- Task.terminal_states() do
        for target_state <- Task.all_states() do
          refute StateMachine.valid_transition?(terminal_state, target_state),
                 "#{terminal_state} should not transition to #{target_state}"
        end
      end
    end

    test "rejects transitioning states going back to active" do
      for transitioning_state <- Task.transitioning_states() do
        for active_state <- Task.active_states() do
          refute StateMachine.valid_transition?(transitioning_state, active_state),
                 "#{transitioning_state} should not transition to #{active_state}"
        end
      end
    end

    test "rejects transitioning states going to wrong terminal" do
      refute StateMachine.valid_transition?(:completing, :failed)
      refute StateMachine.valid_transition?(:failing, :completed)
      refute StateMachine.valid_transition?(:expiring, :cancelled)
      refute StateMachine.valid_transition?(:cancelling, :expired)
    end

    test "rejects running directly to terminal states" do
      refute StateMachine.valid_transition?(:running, :completed)
      refute StateMachine.valid_transition?(:running, :failed)
    end

    test "rejects running directly to terminal states (but allows cancelling)" do
      refute StateMachine.valid_transition?(:running, :cancelled)
      refute StateMachine.valid_transition?(:running, :skipped)
    end
  end

  describe "transition/2" do
    test "returns {:ok, changeset} for valid transitions" do
      task = %Task{status: :pending, type: "test", action: "test"}
      assert {:ok, changeset} = StateMachine.transition(task, :running)
      assert changeset.valid?
      assert Ecto.Changeset.get_change(changeset, :status) == :running
    end

    test "sets started_at when transitioning to running" do
      task = %Task{status: :pending, type: "test", action: "test"}
      {:ok, changeset} = StateMachine.transition(task, :running)
      assert Ecto.Changeset.get_change(changeset, :started_at) != nil
    end

    test "sets completed_at when transitioning to completed" do
      task = %Task{status: :completing, type: "test", action: "test"}
      {:ok, changeset} = StateMachine.transition(task, :completed)
      assert Ecto.Changeset.get_change(changeset, :completed_at) != nil
    end

    test "sets failed_at when transitioning to failed" do
      task = %Task{status: :failing, type: "test", action: "test"}
      {:ok, changeset} = StateMachine.transition(task, :failed)
      assert Ecto.Changeset.get_change(changeset, :failed_at) != nil
    end

    test "returns error for invalid transitions" do
      task = %Task{status: :completed, type: "test", action: "test"}

      assert {:error, {:invalid_transition, :completed, :running}} =
               StateMachine.transition(task, :running)
    end
  end

  describe "valid_transitions/1" do
    test "returns empty list for terminal states" do
      for terminal_state <- Task.terminal_states() do
        assert StateMachine.valid_transitions(terminal_state) == [],
               "#{terminal_state} should have no valid transitions"
      end
    end

    test "returns expected transitions for pending" do
      assert StateMachine.valid_transitions(:pending) == [:running, :skipping, :cancelling]
    end

    test "returns expected transitions for running" do
      assert StateMachine.valid_transitions(:running) == [
               :completing,
               :failing,
               :retrying,
               :waiting,
               :timing_out,
               :cancelling
             ]
    end
  end
end
