defmodule AuthifyWeb.EmailVerificationController do
  use AuthifyWeb, :controller

  alias Authify.Accounts

  def verify(conn, %{"token" => token}) do
    case Accounts.verify_email_with_token(token) do
      {:ok, _user} ->
        conn
        |> put_flash(
          :info,
          "Email verified successfully! You can now log in with your account."
        )
        |> redirect(to: ~p"/login")

      {:error, :token_expired} ->
        conn
        |> put_flash(:error, "Email verification link has expired. Please request a new one.")
        |> redirect(to: ~p"/login")

      {:error, :token_not_found} ->
        conn
        |> put_flash(:error, "Email verification link is invalid.")
        |> redirect(to: ~p"/login")

      {:error, _changeset} ->
        conn
        |> put_flash(:error, "Unable to verify email. Please try again.")
        |> redirect(to: ~p"/login")
    end
  end
end
