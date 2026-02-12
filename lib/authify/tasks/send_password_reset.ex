defmodule Authify.Tasks.SendPasswordReset do
  @moduledoc """
  Task handler for sending password reset emails asynchronously.

  Generates a password reset token and sends the email with the reset link.

  Expects params:
  - "user_id" - ID of the user requesting password reset
  """
  use Authify.Tasks.BasicTask

  require Logger

  alias Authify.{Accounts, Email, Repo}

  @impl true
  def execute(task) do
    user_id = task.params["user_id"]

    # Load user with organization and emails
    user = Accounts.get_user!(user_id) |> Repo.preload([:organization, :emails])

    # Generate password reset token (returns plaintext token)
    case Accounts.generate_password_reset_token(user) do
      {:ok, updated_user, plaintext_token} ->
        # Preload organization and emails for updated user
        user_with_org = Repo.preload(updated_user, [:organization, :emails])

        # Build reset URL with plaintext token
        reset_url = Accounts.build_password_reset_url(user_with_org.organization, plaintext_token)

        # Send the email
        case Email.send_password_reset_email(user_with_org, reset_url) do
          {:ok, metadata} ->
            primary_email = Accounts.User.get_primary_email_value(user_with_org)
            Logger.info("Password reset email sent to #{primary_email}")

            {:ok, %{sent_at: DateTime.utc_now(), email: primary_email, metadata: metadata}}

          {:error, :smtp_not_configured} ->
            Logger.warning(
              "SMTP not configured for organization #{user_with_org.organization.slug}, " <>
                "password reset email not sent"
            )

            {:error, "SMTP not configured for organization"}

          {:error, reason} ->
            Logger.error("Failed to send password reset email: #{inspect(reason)}")
            {:error, "SMTP delivery failed: #{inspect(reason)}"}
        end

      {:error, changeset} ->
        Logger.error("Failed to generate password reset token: #{inspect(changeset.errors)}")
        {:error, "Failed to generate password reset token"}
    end
  end

  @impl true
  def max_retries, do: 3
end
