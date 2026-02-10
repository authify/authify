defmodule Authify.Tasks.EventHandler do
  @moduledoc """
  Simple dispatch layer that maps domain events to task modules.

  EventHandler provides a centralized mechanism for triggering tasks in response
  to application events. Each event name maps to a task handler module that
  implements the event's business logic.

  ## Configuration

  Event mappings are defined as a module attribute:

      @event_tasks %{
        user_created: Authify.Tasks.Handlers.Events.UserCreated,
        user_deleted: Authify.Tasks.Handlers.Events.UserDeleted,
        organization_created: Authify.Tasks.Handlers.Events.OrganizationCreated
      }

  ## Usage

      # In application code where events occur
      EventHandler.handle_event(:user_created, %{
        user_id: user.id,
        organization_id: user.organization_id
      })

  The handler task can then implement org-specific logic:

      defmodule Authify.Tasks.Handlers.Events.UserCreated do
        use Authify.Tasks.BasicTask

        def execute(task) do
          org = Organizations.get_organization!(task.organization_id)
          user = Accounts.get_user!(task.params["user_id"])

          # Create tasks based on org settings
          tasks = []
          tasks = if org.settings["audit_enabled"], do: [audit_task(user) | tasks], else: tasks
          tasks = if org.settings["welcome_email"], do: [welcome_task(user) | tasks], else: tasks

          Enum.each(tasks, &Tasks.create_and_enqueue_task/1)
          {:ok, %{tasks_created: length(tasks)}}
        end
      end

  ## Future Enhancements

  - Database-driven event configuration
  - Event versioning and schema validation
  - Pub/sub integration for distributed systems
  """

  alias Authify.Tasks

  # Event name to handler module mapping
  @event_tasks %{
    user_created: Authify.Tasks.Handlers.Events.UserCreated,
    user_deleted: Authify.Tasks.Handlers.Events.UserDeleted,
    organization_created: Authify.Tasks.Handlers.Events.OrganizationCreated
  }

  @doc """
  Returns the configured event-to-handler mapping.
  """
  def event_tasks, do: @event_tasks

  @doc """
  Handles a domain event by creating and enqueuing a task for the associated handler.

  Returns `{:ok, task}` if the event is known and the task was created successfully,
  or `{:error, reason}` if the event is unknown or task creation fails.

  ## Parameters

    * `event_name` - Atom identifying the event (e.g., `:user_created`)
    * `params` - Map containing event data (must include `organization_id`)

  ## Examples

      iex> EventHandler.handle_event(:user_created, %{
      ...>   user_id: "123",
      ...>   organization_id: 1
      ...> })
      {:ok, %Task{}}

      iex> EventHandler.handle_event(:unknown_event, %{})
      {:error, :unknown_event}
  """
  def handle_event(event_name, params) when is_atom(event_name) and is_map(params) do
    case Map.get(@event_tasks, event_name) do
      nil ->
        {:error, :unknown_event}

      handler_module ->
        create_event_task(handler_module, params)
    end
  end

  defp create_event_task(handler_module, params) do
    {type, action} = module_to_type_action(handler_module)

    organization_id = Map.get(params, :organization_id) || Map.get(params, "organization_id")

    # Remove organization_id from params since it's stored as a separate field
    task_params =
      params
      |> Map.delete(:organization_id)
      |> Map.delete("organization_id")

    task_attrs = %{
      type: type,
      action: action,
      params: task_params,
      organization_id: organization_id
    }

    Tasks.create_and_enqueue_task(task_attrs)
  end

  defp module_to_type_action(module) when is_atom(module) do
    parts = Module.split(module)

    case Enum.reverse(parts) do
      [action, "Events", "Handlers", "Tasks", "Authify" | _rest] ->
        {"events", Macro.underscore(action)}

      [action, type | _] ->
        {Macro.underscore(type), Macro.underscore(action)}
    end
  end
end
