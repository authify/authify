defmodule AuthifyWeb.Auth.ErrorHandler do
  @moduledoc """
  Guardian error handler for authentication failures.
  """

  import Plug.Conn
  import Phoenix.Controller

  def auth_error(conn, {_type, _reason}, _opts) do
    conn
    |> delete_session(:guardian_default_token)
    |> put_flash(:error, "Authentication required. Please log in.")
    |> redirect(to: "/login")
    |> halt()
  end
end
