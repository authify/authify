defmodule Authify.Tasks.SendEmailVerification do
  @moduledoc """
  Task handler for sending email verification emails asynchronously.

  Generates an email verification token and sends the email with the verification link.

  Expects params:
  - "user_id" - ID of the user to send verification email to
  """
  use Authify.Tasks.BasicTask

  require Logger

  alias Authify.{Accounts, Email, Repo}

  @impl true
  def execute(task) do
    user_id = task.params["user_id"]

    # Load user with organization and emails
    user = Accounts.get_user!(user_id) |> Repo.preload([:organization, :emails])

    # Generate email verification token for user's primary email
    case Accounts.generate_email_verification_token(user) do
      {:ok, email, plaintext_token} ->
        # Build verification URL with plaintext token
        verification_url =
          Accounts.build_email_verification_url(user.organization, plaintext_token)

        # Send the email
        case Email.send_email_verification_email(user, verification_url) do
          {:ok, metadata} ->
            Logger.info("Email verification sent to #{email.value}")

            {:ok, %{sent_at: DateTime.utc_now(), email: email.value, metadata: metadata}}

          {:error, :smtp_not_configured} ->
            Logger.warning(
              "SMTP not configured for organization #{user.organization.slug}, " <>
                "verification email not sent to #{email.value}"
            )

            {:error, "SMTP not configured for organization"}

          {:error, reason} ->
            Logger.error(
              "Failed to send verification email to #{email.value}: #{inspect(reason)}"
            )

            {:error, "SMTP delivery failed: #{inspect(reason)}"}
        end

      {:error, changeset} ->
        Logger.error("Failed to generate email verification token: #{inspect(changeset.errors)}")
        {:error, "Failed to generate verification token"}
    end
  end

  @impl true
  def max_retries, do: 3
end
