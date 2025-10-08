defmodule AuthifyWeb.Auth.Pipeline do
  @moduledoc """
  Guardian authentication pipeline for browser sessions.
  """

  use Guardian.Plug.Pipeline,
    otp_app: :authify,
    module: Authify.Guardian,
    error_handler: AuthifyWeb.Auth.ErrorHandler

  plug Guardian.Plug.VerifySession, claims: %{"typ" => "access"}
  plug Guardian.Plug.VerifyHeader, claims: %{"typ" => "access"}
  plug Guardian.Plug.LoadResource, allow_blank: true
end
