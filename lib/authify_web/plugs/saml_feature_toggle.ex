defmodule AuthifyWeb.Plugs.SamlFeatureToggle do
  @moduledoc """
  Plug to enforce the `:allow_saml` organization feature toggle for the SAML
  identity provider endpoints.

  When SAML is disabled for an organization the protocol endpoints
  (`/saml/metadata`, `/saml/sso`, `/saml/continue`, `/saml/slo`) must not serve
  requests, so this plug returns a 404 to avoid advertising an IdP that is
  turned off.

  The plug requires `conn.assigns.current_organization` to be set by the
  `AuthifyWeb.Plugs.OrganizationPlug`, which must run earlier in the pipeline.
  """
  import Plug.Conn

  alias Authify.Configurations

  def init(opts), do: opts

  def call(conn, _opts) do
    organization = conn.assigns[:current_organization]

    if organization && Configurations.allow_saml?(organization) do
      conn
    else
      conn
      |> put_resp_content_type("text/plain")
      |> send_resp(:not_found, "SAML is not enabled for this organization")
      |> halt()
    end
  end
end
