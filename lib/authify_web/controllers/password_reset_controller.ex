defmodule AuthifyWeb.PasswordResetController do
  use AuthifyWeb, :controller

  alias Authify.Accounts

  def new(conn, _params) do
    render(conn, :new)
  end

  def create(conn, %{"password_reset" => %{"email" => email}}) do
    case Accounts.get_user_by_email(email) do
      %Accounts.User{} = user ->
        case Accounts.generate_password_reset_token(user) do
          {:ok, updated_user, plaintext_token} ->
            # Preload organization for email
            user_with_org = Authify.Repo.preload(updated_user, :organization)

            # Build the password reset URL
            reset_url = build_password_reset_url(user_with_org.organization, plaintext_token)

            # Send password reset email
            case Authify.Email.send_password_reset_email(user_with_org, reset_url) do
              {:ok, _metadata} ->
                require Logger
                Logger.info("Password reset email sent to #{user.email}")

              {:error, :smtp_not_configured} ->
                require Logger

                Logger.warning(
                  "SMTP not configured for organization #{user_with_org.organization.slug}, password reset requested but email not sent"
                )

              {:error, reason} ->
                require Logger
                Logger.error("Failed to send password reset email: #{inspect(reason)}")
            end

            # Always show generic message (don't reveal if email sent or not)
            conn
            |> put_flash(
              :info,
              "If an account with that email exists, you will receive password reset instructions."
            )
            |> redirect(to: ~p"/login")

          {:error, _changeset} ->
            conn
            |> put_flash(:error, "Unable to process password reset request.")
            |> render(:new)
        end

      nil ->
        # Don't reveal whether user exists - same response as success
        conn
        |> put_flash(
          :info,
          "If an account with that email exists, you will receive password reset instructions."
        )
        |> redirect(to: ~p"/login")
    end
  end

  # Build the full URL for resetting password
  defp build_password_reset_url(organization, token) do
    # Get the effective email link domain for this organization
    # (uses configured email_link_domain or falls back to default domain)
    domain = Authify.Organizations.get_email_link_domain(organization)

    # Build the reset URL with proper protocol/port for environment
    base_url =
      if Mix.env() == :dev do
        "http://#{domain}:4000"
      else
        "https://#{domain}"
      end

    "#{base_url}/password_reset/#{token}"
  end

  def edit(conn, %{"token" => token}) do
    case Accounts.get_user_by_password_reset_token(token) do
      %Accounts.User{} = user ->
        if Accounts.User.valid_password_reset_token?(user) do
          changeset = Accounts.change_user_password(user)
          render(conn, :edit, token: token, changeset: changeset)
        else
          conn
          |> put_flash(:error, "Password reset link is invalid or has expired.")
          |> redirect(to: ~p"/password_reset/new")
        end

      nil ->
        conn
        |> put_flash(:error, "Password reset link is invalid or has expired.")
        |> redirect(to: ~p"/password_reset/new")
    end
  end

  def update(conn, %{"token" => token, "user" => password_params}) do
    case Accounts.reset_password_with_token(token, password_params) do
      {:ok, _user} ->
        conn
        |> put_flash(
          :info,
          "Password reset successfully. You can now log in with your new password."
        )
        |> redirect(to: ~p"/login")

      {:error, :token_expired} ->
        conn
        |> put_flash(:error, "Password reset link has expired. Please request a new one.")
        |> redirect(to: ~p"/password_reset/new")

      {:error, :token_not_found} ->
        conn
        |> put_flash(:error, "Password reset link is invalid.")
        |> redirect(to: ~p"/password_reset/new")

      {:error, :invalid_token} ->
        conn
        |> put_flash(:error, "Password reset link is invalid.")
        |> redirect(to: ~p"/password_reset/new")

      {:error, %Ecto.Changeset{} = changeset} ->
        render(conn, :edit, token: token, changeset: changeset)
    end
  end
end
