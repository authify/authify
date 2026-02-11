defmodule Authify.Tasks.SendInvitation do
  @moduledoc """
  Task handler for sending invitation emails asynchronously.

  Expects params:
  - "invitation_id" - ID of the invitation to send
  """
  use Authify.Tasks.BasicTask

  require Logger

  alias Authify.{Accounts, Email, Repo}

  @impl true
  def execute(task) do
    invitation_id = task.params["invitation_id"]

    # Load invitation with required associations
    invitation =
      Accounts.get_invitation!(invitation_id)
      |> Repo.preload([:organization, invited_by: :emails])

    # Build accept URL from invitation
    accept_url = Accounts.build_invitation_accept_url(invitation)

    case Email.send_invitation_email(invitation, accept_url) do
      {:ok, metadata} ->
        Logger.info("Invitation email sent to #{invitation.email}")
        {:ok, %{sent_at: DateTime.utc_now(), email: invitation.email, metadata: metadata}}

      {:error, :smtp_not_configured} ->
        Logger.warning(
          "SMTP not configured for organization #{invitation.organization.slug}, " <>
            "invitation email not sent to #{invitation.email}"
        )

        {:error, "SMTP not configured for organization"}

      {:error, reason} ->
        Logger.error("Failed to send invitation email to #{invitation.email}: #{inspect(reason)}")
        {:error, "SMTP delivery failed: #{inspect(reason)}"}
    end
  end

  @impl true
  def max_retries, do: 3
end
