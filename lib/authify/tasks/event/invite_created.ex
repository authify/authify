defmodule Authify.Tasks.Event.InviteCreated do
  @moduledoc """
  Event handler triggered when an invitation is created.

  Orchestrates the workflow for new invitations, which includes
  sending the invitation email to the invitee.
  """
  use Authify.Tasks.BasicTask

  alias Authify.Tasks

  @impl true
  def execute(task) do
    invitation_id = task.params["invitation_id"]

    # Create task to send invitation email
    email_task_attrs = %{
      type: "send_invitation",
      action: "execute",
      params: %{"invitation_id" => invitation_id},
      organization_id: task.organization_id,
      timeout_seconds: 30
    }

    case Tasks.create_and_enqueue_task(email_task_attrs) do
      {:ok, email_task} ->
        {:ok, %{email_task_id: email_task.id}}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
