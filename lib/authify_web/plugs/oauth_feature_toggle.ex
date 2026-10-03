defmodule AuthifyWeb.Plugs.OAuthFeatureToggle do
  @moduledoc """
  Plug to enforce the `:allow_oauth` organization feature toggle on the
  third-party OAuth2/OIDC identity provider surface.

  When OAuth is disabled for an organization the browser authorize/consent
  endpoints, the userinfo endpoint, and OIDC discovery must not serve requests,
  so this plug returns a 404 to avoid advertising functionality that is off.

  It intentionally does not gate the `client_credentials` grant or the
  Management API, which rely on the same OAuth tables and token endpoint.

  The plug requires `conn.assigns.current_organization` to be set by the
  `AuthifyWeb.Plugs.OrganizationPlug`, which must run earlier in the pipeline.
  """
  import Plug.Conn

  alias Authify.Configurations

  def init(opts), do: opts

  def call(conn, _opts) do
    organization = conn.assigns[:current_organization]

    if organization && Configurations.allow_oauth?(organization) do
      conn
    else
      conn
      |> put_resp_content_type("text/plain")
      |> send_resp(:not_found, "OAuth2/OIDC is not enabled for this organization")
      |> halt()
    end
  end
end
