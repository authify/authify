defmodule Authify.Tasks.WorkflowTaskTest do
  use Authify.DataCase, async: false
  use Oban.Testing, repo: Authify.Repo

  alias Authify.Tasks
  alias Authify.Tasks.Workers.TaskExecutor

  import Authify.AccountsFixtures

  setup do
    org = organization_fixture()
    %{org: org}
  end

  defp insert_workflow(org, handler_module, attrs \\ %{}) do
    default = %{
      type: handler_to_type(handler_module),
      action: "execute",
      organization_id: org.id,
      params: %{}
    }

    {:ok, task} = Tasks.create_and_enqueue_task(Map.merge(default, attrs))
    task
  end

  defp perform_task(task) do
    TaskExecutor.perform(%Oban.Job{args: %{"task_id" => task.id}})
  end

  defp handler_to_type(module) do
    # Convert Authify.Tasks.TestWorkflowSuccess → "test_workflow_success"
    module
    |> Module.split()
    |> List.last()
    |> Macro.underscore()
  end

  describe "workflow success" do
    test "runs steps in order and accumulates context", %{org: org} do
      Oban.Testing.with_testing_mode(:manual, fn ->
        workflow = insert_workflow(org, Authify.Tasks.TestWorkflowSuccess)

        # First cycle schedules step one
        assert :ok = perform_task(workflow)

        [step_one] = Tasks.list_children(workflow)
        assert step_one.metadata["step_index"] == 0

        # Execute step one
        assert :ok = perform_task(step_one)

        # Workflow advances and schedules step two
        assert :ok = perform_task(Tasks.get_task!(workflow.id))
        [_, step_two] = Tasks.list_children(workflow)
        assert step_two.metadata["step_index"] == 1

        # Execute step two
        assert :ok = perform_task(step_two)

        # Final run completes workflow after step two completion
        assert :ok = perform_task(Tasks.get_task!(workflow.id))

        completed = Tasks.get_task!(workflow.id)
        assert completed.status == :completed
        assert completed.metadata["current_step"] == 2
        assert completed.metadata["context"] == %{"step_one" => 1, "step_two" => 2}

        children = Tasks.list_children(workflow)
        assert Enum.count(children) == 2
        assert Enum.map(children, & &1.status) == [:completed, :completed]
      end)
    end
  end

  describe "workflow failure handling" do
    test "stops on failure when continue_on_failure? is false", %{org: org} do
      Oban.Testing.with_testing_mode(:manual, fn ->
        workflow = insert_workflow(org, Authify.Tasks.TestWorkflowFailStop)

        # Schedule failing step
        assert :ok = perform_task(workflow)
        [step_one] = Tasks.list_children(workflow)

        # Execute failing step
        assert :ok = perform_task(step_one)

        # Workflow attempts to advance and sees failed child
        assert :ok = perform_task(Tasks.get_task!(workflow.id))

        failed = Tasks.get_task!(workflow.id)
        assert failed.status == :failed
        assert failed.errors["final"]["type"] == "workflow_step_failed"
      end)
    end

    test "continues to next step when continue_on_failure? is true", %{org: org} do
      Oban.Testing.with_testing_mode(:manual, fn ->
        workflow = insert_workflow(org, Authify.Tasks.TestWorkflowFailContinue)

        # Schedule failing step
        assert :ok = perform_task(workflow)
        [step_one] = Tasks.list_children(workflow)

        # Execute failing step
        assert :ok = perform_task(step_one)

        # Workflow advances despite failure and schedules next step
        assert :ok = perform_task(Tasks.get_task!(workflow.id))
        [_, step_two] = Tasks.list_children(workflow)

        # Execute second step
        assert :ok = perform_task(step_two)

        # Final run completes after second step
        assert :ok = perform_task(Tasks.get_task!(workflow.id))

        completed = Tasks.get_task!(workflow.id)
        assert completed.status == :completed
        assert completed.metadata["current_step"] == 2

        children = Tasks.list_children(workflow)
        assert Enum.map(children, & &1.status) == [:failed, :completed]
      end)
    end
  end
end
