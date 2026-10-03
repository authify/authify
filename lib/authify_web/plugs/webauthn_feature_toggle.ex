defmodule AuthifyWeb.Plugs.WebAuthnFeatureToggle do
  @moduledoc """
  Plug to enforce the `:allow_webauthn` organization feature toggle on WebAuthn
  credential registration.

  Registration is blocked when WebAuthn is disabled, returning a 404 to match
  the other feature toggles. Credential management (listing and revoking
  existing credentials) is intentionally left available so users can clean up
  credentials while registration is off.

  The plug requires `conn.assigns.current_organization` to be set by the
  `AuthifyWeb.Plugs.OrganizationPlug`, which must run earlier in the pipeline.
  """
  import Plug.Conn

  alias Authify.Configurations

  def init(opts), do: opts

  def call(conn, _opts) do
    organization = conn.assigns[:current_organization]

    if organization && Configurations.allow_webauthn?(organization) do
      conn
    else
      conn
      |> put_resp_content_type("text/plain")
      |> send_resp(:not_found, "WebAuthn is not enabled for this organization")
      |> halt()
    end
  end
end
