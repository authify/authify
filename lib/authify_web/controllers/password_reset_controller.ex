defmodule AuthifyWeb.PasswordResetController do
  use AuthifyWeb, :controller

  alias Authify.Accounts
  alias AuthifyWeb.Helpers.AuditHelper

  def new(conn, _params) do
    render(conn, :new)
  end

  def create(conn, %{"password_reset" => %{"email" => email}}) do
    case Accounts.get_user_by_email(email) do
      %Accounts.User{} = user ->
        # Preload organization for event
        user = Authify.Repo.preload(user, :organization)

        # Emit event to trigger password reset workflow (token generation + email)
        case Authify.Tasks.EventHandler.handle_event(:password_reset_requested, %{
               user_id: user.id,
               organization_id: user.organization_id
             }) do
          {:ok, _task} ->
            require Logger
            Logger.info("Password reset workflow triggered for user #{user.id}")

          {:error, reason} ->
            require Logger
            Logger.error("Failed to trigger password reset workflow: #{inspect(reason)}")
        end

        # Always show generic message (don't reveal if email sent or not)
        conn
        |> put_flash(
          :info,
          "If an account with that email exists, you will receive password reset instructions."
        )
        |> redirect(to: ~p"/login")

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
      {:ok, user} ->
        AuditHelper.log_password_reset_completed(conn, user, extra_metadata: %{"source" => "web"})

        conn
        |> put_flash(
          :info,
          "Password reset successfully. You can now log in with your new password."
        )
        |> redirect(to: ~p"/login")

      {:error, :token_expired} ->
        with %Accounts.User{} = user <-
               Accounts.get_user_by_password_reset_token_including_expired(token) do
          AuditHelper.log_password_reset_failure(conn, user, :token_expired,
            extra_metadata: %{"source" => "web"}
          )
        end

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
        user = Authify.Repo.preload(changeset.data, :organization)

        AuditHelper.log_password_reset_failure(conn, user, :validation_failed,
          errors: changeset,
          extra_metadata: %{"source" => "web"}
        )

        render(conn, :edit, token: token, changeset: changeset)
    end
  end
end
