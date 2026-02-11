defmodule Authify.Tasks.WorkflowTask do
  @moduledoc """
  Behavior for orchestrating multi-step workflows using task handlers as steps.

  Workflows run steps asynchronously as regular tasks. Each step is created as a
  child task of the workflow and executed via `TaskExecutor`. When a step reaches
  a terminal state, the workflow is automatically re-scheduled to advance to the
  next step. Context (params + results) accumulates between steps.

  ## Callbacks

      @callback workflow_steps() :: [module()]
      @callback continue_on_failure?() :: boolean()

  `workflow_steps/0` returns the list of task modules to execute in order.
  `continue_on_failure?/0` controls whether the workflow proceeds after a step
  failure (defaults to `false`).
  """

  alias Authify.Tasks
  alias Authify.Tasks.Task
  alias Authify.Tasks.Workers.TaskExecutor

  @type task :: %Task{}
  @type context :: map()

  @callback workflow_steps() :: [module()]
  @callback continue_on_failure?() :: boolean()

  defmacro __using__(_opts) do
    quote do
      use Authify.Tasks.BasicTask

      @behaviour Authify.Tasks.WorkflowTask

      @impl Authify.Tasks.BasicTask
      def execute(task) do
        Authify.Tasks.WorkflowTask.execute_workflow(task, __MODULE__)
      end

      @impl Authify.Tasks.WorkflowTask
      def continue_on_failure?, do: false

      defoverridable continue_on_failure?: 0, execute: 1
    end
  end

  @doc false
  def execute_workflow(%Task{} = task, handler) do
    steps = handler.workflow_steps()
    metadata = task.metadata || %{}
    context = Map.get(metadata, "context", task.params || %{})
    current_step = Map.get(metadata, "current_step", 0)

    do_execute(task, handler, steps, current_step, context)
  end

  defp do_execute(_task, _handler, [], _index, context), do: {:ok, context}

  defp do_execute(%Task{} = task, handler, steps, index, context) do
    if index >= length(steps) do
      {:ok, context}
    else
      step_module = Enum.at(steps, index)
      step_child = current_step_child(task, index)

      case step_child do
        nil ->
          schedule_step(task, step_module, context, index)

        %Task{} = child ->
          handle_existing_child(task, handler, steps, index, context, child, step_module)
      end
    end
  end

  defp handle_existing_child(task, handler, steps, index, context, %Task{} = child, step_module) do
    status = child.status
    running_statuses = Task.active_states() ++ Task.transitioning_states()

    cond do
      status in running_statuses ->
        ensure_waiting(task)
        schedule_self(task)
        {:wait, :step_running}

      status == :completed ->
        new_context = merge_context(context, child)
        task = persist_progress(task, index + 1, new_context)
        do_execute(task, handler, steps, index + 1, new_context)

      status in [:failed, :expired, :timed_out, :cancelled, :skipped] ->
        if handler.continue_on_failure?() do
          task = persist_progress(task, index + 1, context)
          do_execute(task, handler, steps, index + 1, context)
        else
          {:error,
           %{
             type: "workflow_step_failed",
             step: inspect(step_module),
             status: status,
             errors: child.errors || %{}
           }}
        end
    end
  end

  defp current_step_child(%Task{id: parent_id}, step_index) do
    Tasks.list_children(%Task{id: parent_id})
    |> Enum.find(fn child -> Map.get(child.metadata || %{}, "step_index") == step_index end)
  end

  defp schedule_step(%Task{} = workflow, step_module, context, step_index) do
    {type, action} = module_to_type_action(step_module)

    attrs = %{
      type: type,
      action: action,
      params: context,
      organization_id: workflow.organization_id,
      correlation_id: workflow.correlation_id,
      parent_id: workflow.id,
      metadata: %{"step_index" => step_index}
    }

    case Tasks.create_and_enqueue_task(attrs) do
      {:ok, _child} ->
        ensure_waiting(workflow)
        schedule_self(workflow)
        {:wait, :step_scheduled}

      {:error, _err} ->
        {:error, %{type: "workflow_step_creation_failed", step: inspect(step_module)}}
    end
  end

  defp ensure_waiting(%Task{status: :waiting}), do: :ok

  defp ensure_waiting(%Task{} = task) do
    Tasks.transition_task(task, :waiting)
    :ok
  end

  defp schedule_self(%Task{} = task, delay_seconds \\ 1) do
    TaskExecutor.schedule_execution(task, delay_seconds)
    :ok
  end

  defp merge_context(_context, %Task{params: params, results: results}) do
    params = params || %{}
    results = results || %{}
    Map.merge(params, results)
  end

  defp persist_progress(%Task{} = task, next_step, context) do
    metadata =
      (task.metadata || %{}) |> Map.put("current_step", next_step) |> Map.put("context", context)

    case Tasks.update_task(task, %{metadata: metadata}) do
      {:ok, updated} -> updated
      {:error, _} -> task
    end
  end

  defp module_to_type_action(module) when is_atom(module) do
    case Enum.reverse(Module.split(module)) do
      # Event handlers: Authify.Tasks.Event.* → {"event", action}
      [action, "Event", "Tasks", "Authify" | _rest] ->
        {"event", Macro.underscore(action)}

      # Regular tasks: Authify.Tasks.* → {type, "execute"}
      [type, "Tasks", "Authify" | _rest] ->
        {Macro.underscore(type), "execute"}

      # Fallback for any other pattern
      [last | _] ->
        {Macro.underscore(last), "execute"}
    end
  end
end
