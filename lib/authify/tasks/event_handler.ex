defmodule Authify.Tasks.EventHandler do
  @moduledoc """
  Simple dispatch layer that maps domain events to event handler tasks.

  EventHandler provides a centralized mechanism for responding to application
  events. When a domain event occurs, EventHandler creates an event handler task
  that orchestrates the workflow for that event, which may include creating
  additional child tasks.

  ## Architecture

  - **Domain Events**: Business occurrences (e.g., `:invite_created`, `:password_reset_requested`)
  - **Event Handlers**: Tasks at `Authify.Tasks.Handlers.*` that orchestrate responses
  - **Child Tasks**: Regular tasks at `Authify.Tasks.*` that perform specific actions

  ## Configuration

  Event mappings are defined as a module attribute:

      @event_tasks %{
        invite_created: Authify.Tasks.Event.InviteCreated,
        password_reset_requested: Authify.Tasks.Event.PasswordResetRequested,
        email_verification_needed: Authify.Tasks.Event.EmailVerificationNeeded
      }

  ## Usage

      # In application code where domain events occur
      EventHandler.handle_event(:invite_created, %{
        invitation_id: invitation.id,
        organization_id: invitation.organization_id
      })

  ## Event Handler Example

  Event handlers orchestrate workflows and create child tasks:

      defmodule Authify.Tasks.Event.InviteCreated do
        use Authify.Tasks.BasicTask

        def execute(task) do
          # Create child task to send invitation email
          email_task = %{
            type: "send_invitation",  # Maps to Authify.Tasks.SendInvitation
            action: "execute",
            params: %{"invitation_id" => task.params["invitation_id"]},
            organization_id: task.organization_id
          }

          Tasks.create_and_enqueue_task(email_task)
        end
      end

  ## Regular Task Example

  Child tasks perform specific actions:

      defmodule Authify.Tasks.SendInvitation do
        use Authify.Tasks.BasicTask

        def execute(task) do
          # Load invitation and send email
          invitation = Accounts.get_invitation!(task.params["invitation_id"])
          Email.send_invitation_email(invitation)
        end
      end

  ## Task Resolution

  - Event handlers: `type: "event", action: "invite_created"` → `Authify.Tasks.Event.InviteCreated`
  - Regular tasks: `type: "send_invitation", action: "execute"` → `Authify.Tasks.SendInvitation`

  ## Future Enhancements

  - Database-driven event configuration
  - Event versioning and schema validation
  - Pub/sub integration for distributed systems
  """

  alias Authify.Tasks

  # Event name to handler module mapping
  @event_tasks %{
    invite_created: Authify.Tasks.Event.InviteCreated,
    password_reset_requested: Authify.Tasks.Event.PasswordResetRequested,
    email_verification_needed: Authify.Tasks.Event.EmailVerificationNeeded
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

    * `event_name` - Atom identifying the event (e.g., `:invite_created`)
    * `params` - Map containing event data (must include `organization_id`)

  ## Examples

      iex> EventHandler.handle_event(:invite_created, %{
      ...>   invitation_id: "123",
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
      [action, "Event", "Tasks", "Authify" | _rest] ->
        # Event handler: Authify.Tasks.Event.{Action}
        {"event", Macro.underscore(action)}

      [type, "Tasks", "Authify" | _rest] ->
        # Regular task: Authify.Tasks.{Type}
        {Macro.underscore(type), "execute"}
    end
  end
end
