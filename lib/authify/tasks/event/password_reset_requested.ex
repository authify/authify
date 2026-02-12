defmodule Authify.Tasks.Event.PasswordResetRequested do
  @moduledoc """
  Event handler triggered when a user requests a password reset.

  Orchestrates the workflow for password resets, which includes
  generating the reset token and sending the password reset email.
  """
  use Authify.Tasks.BasicTask

  alias Authify.Tasks

  @impl true
  def execute(task) do
    user_id = task.params["user_id"]

    # Create task to generate token and send password reset email
    email_task_attrs = %{
      type: "send_password_reset",
      action: "execute",
      params: %{"user_id" => user_id},
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
