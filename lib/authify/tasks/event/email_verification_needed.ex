defmodule Authify.Tasks.Event.EmailVerificationNeeded do
  @moduledoc """
  Event handler triggered when a user needs email verification.

  Orchestrates the workflow for email verification, which includes
  generating the verification token and sending the verification email.
  """
  use Authify.Tasks.BasicTask

  alias Authify.Tasks

  @impl true
  def execute(task) do
    user_id = task.params["user_id"]

    # Create task to generate token and send verification email
    email_task_attrs = %{
      type: "send_email_verification",
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
