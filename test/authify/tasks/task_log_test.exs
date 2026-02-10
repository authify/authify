defmodule Authify.Tasks.TaskLogTest do
  @moduledoc """
  Tests for the TaskLog schema and validations.
  """
  use Authify.DataCase, async: true

  alias Authify.Tasks.{Task, TaskLog}

  describe "changeset/2" do
    test "valid changeset with required fields" do
      task = insert_task()

      attrs = %{
        task_id: task.id,
        log_data: ~s([[1234567890, "Task started"]])
      }

      changeset = TaskLog.changeset(%TaskLog{}, attrs)
      assert changeset.valid?
    end

    test "requires log_data and task_id" do
      changeset = TaskLog.changeset(%TaskLog{}, %{})
      refute changeset.valid?
      assert %{log_data: ["can't be blank"]} = errors_on(changeset)
      assert %{task_id: ["can't be blank"]} = errors_on(changeset)
    end

    test "validates foreign key constraint for task_id" do
      attrs = %{
        task_id: Ecto.UUID.generate(),
        log_data: ~s([[1234567890, "Task started"]])
      }

      changeset = TaskLog.changeset(%TaskLog{}, attrs)
      assert changeset.valid?

      assert {:error, changeset} = Repo.insert(changeset)
      assert %{task_id: ["does not exist"]} = errors_on(changeset)
    end
  end

  defp insert_task do
    Repo.insert!(%Task{
      type: "test",
      action: "test_action",
      status: :pending,
      params: %{}
    })
  end
end
