defmodule Authify.Tasks.TaskTest do
  @moduledoc """
  Tests for the Task schema, validations, and state management.
  """
  use Authify.DataCase, async: true

  alias Authify.Tasks.Task

  describe "changeset/2" do
    test "valid changeset with required fields" do
      attrs = %{
        type: "email",
        action: "send_invitation",
        status: :pending,
        params: %{"user_id" => "123"}
      }

      changeset = Task.changeset(%Task{}, attrs)
      assert changeset.valid?
    end

    test "applies default values" do
      attrs = %{
        type: "email",
        action: "send_invitation",
        status: :pending
      }

      changeset = Task.changeset(%Task{}, attrs)
      assert changeset.valid?
      assert get_field(changeset, :priority) == 0
      assert get_field(changeset, :max_retries) == 3
      assert get_field(changeset, :retry_count) == 0
      assert get_field(changeset, :params) == %{}
      assert get_field(changeset, :results) == %{}
      assert get_field(changeset, :errors) == %{}
      assert get_field(changeset, :metadata) == %{}
    end

    test "requires type and action" do
      changeset = Task.changeset(%Task{}, %{})
      refute changeset.valid?
      assert %{type: ["can't be blank"]} = errors_on(changeset)
      assert %{action: ["can't be blank"]} = errors_on(changeset)
      # status has a default value of :pending, so it's not required
    end

    test "validates status is in allowed states" do
      attrs = %{
        type: "email",
        action: "send_invitation",
        status: :invalid_status
      }

      changeset = Task.changeset(%Task{}, attrs)
      refute changeset.valid?
      assert %{status: ["is invalid"]} = errors_on(changeset)
    end

    test "accepts all valid states" do
      for state <- Task.all_states() do
        attrs = %{
          type: "email",
          action: "send_invitation",
          status: state
        }

        changeset = Task.changeset(%Task{}, attrs)
        assert changeset.valid?, "State #{state} should be valid"
      end
    end

    test "validates priority is non-negative" do
      attrs = %{
        type: "email",
        action: "send_invitation",
        status: :pending,
        priority: -1
      }

      changeset = Task.changeset(%Task{}, attrs)
      refute changeset.valid?
      assert %{priority: ["must be greater than or equal to 0"]} = errors_on(changeset)
    end

    test "validates max_retries is non-negative" do
      attrs = %{
        type: "email",
        action: "send_invitation",
        status: :pending,
        max_retries: -1
      }

      changeset = Task.changeset(%Task{}, attrs)
      refute changeset.valid?
      assert %{max_retries: ["must be greater than or equal to 0"]} = errors_on(changeset)
    end

    test "validates timeout_seconds is positive" do
      attrs = %{
        type: "email",
        action: "send_invitation",
        status: :pending,
        timeout_seconds: 0
      }

      changeset = Task.changeset(%Task{}, attrs)
      refute changeset.valid?
      assert %{timeout_seconds: ["must be greater than 0"]} = errors_on(changeset)
    end

    test "sorts params keys alphabetically" do
      attrs = %{
        type: "email",
        action: "send_invitation",
        status: :pending,
        params: %{"z_key" => 1, "a_key" => 2, "m_key" => 3}
      }

      changeset = Task.changeset(%Task{}, attrs)
      assert changeset.valid?

      # Get the params and encode to JSON to verify key ordering
      params = get_change(changeset, :params)
      json = Jason.encode!(params)
      assert json == ~s({"a_key":2,"m_key":3,"z_key":1})
    end

    test "sorts nested params keys alphabetically" do
      attrs = %{
        type: "email",
        action: "send_invitation",
        status: :pending,
        params: %{
          "z_key" => %{"nested_z" => 1, "nested_a" => 2},
          "a_key" => [%{"list_z" => 3, "list_a" => 4}]
        }
      }

      changeset = Task.changeset(%Task{}, attrs)
      assert changeset.valid?

      params = get_change(changeset, :params)
      json = Jason.encode!(params)

      assert json ==
               ~s({"a_key":[{"list_a":4,"list_z":3}],"z_key":{"nested_a":2,"nested_z":1}})
    end
  end

  describe "state categories" do
    test "active_states/0 returns active states" do
      assert Task.active_states() == [:scheduled, :pending, :running, :waiting, :retrying]
    end

    test "transitioning_states/0 returns transitioning states" do
      assert Task.transitioning_states() == [
               :completing,
               :failing,
               :expiring,
               :cancelling,
               :timing_out,
               :skipping
             ]
    end

    test "terminal_states/0 returns terminal states" do
      assert Task.terminal_states() == [
               :completed,
               :failed,
               :expired,
               :timed_out,
               :cancelled,
               :skipped
             ]
    end

    test "all_states/0 returns all states" do
      assert length(Task.all_states()) == 17
    end

    test "non_terminal_states/0 returns active and transitioning states" do
      assert Task.non_terminal_states() ==
               Task.active_states() ++ Task.transitioning_states()
    end
  end
end
