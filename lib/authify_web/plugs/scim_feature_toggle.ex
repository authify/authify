defmodule AuthifyWeb.Plugs.ScimFeatureToggle do
  @moduledoc """
  Plug to enforce the SCIM inbound provisioning feature toggle.

  This plug checks if SCIM 2.0 Service Provider endpoints are enabled for
  the organization. If disabled, it returns a 404 error to prevent access
  to SCIM endpoints.

  The plug requires that conn.assigns.current_organization is already set
  by the OrganizationPlug, which runs earlier in the pipeline.
  """
  import Plug.Conn
  import Phoenix.Controller

  alias Authify.Configurations

  def init(opts), do: opts

  def call(conn, _opts) do
    organization = conn.assigns[:current_organization]

    if organization && scim_enabled?(organization) do
      conn
    else
      # Return 404 to prevent feature discovery when SCIM is disabled
      conn
      |> put_status(:not_found)
      |> put_resp_content_type("application/scim+json")
      |> json(%{
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        status: "404",
        detail: "SCIM provisioning is not enabled for this organization"
      })
      |> halt()
    end
  end

  defp scim_enabled?(organization) do
    # Default to true if not configured (backwards compatibility)
    Configurations.get_organization_setting(organization, :scim_inbound_provisioning_enabled) !=
      false
  end
end
