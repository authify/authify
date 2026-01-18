defmodule AuthifyWeb.SCIM.ServiceProviderConfigController do
  @moduledoc """
  SCIM 2.0 ServiceProviderConfig endpoint per RFC 7644 Section 4.

  Returns static configuration describing the SCIM service provider's
  capabilities and supported features.
  """

  use AuthifyWeb.SCIM.BaseController

  @doc """
  GET /scim/v2/ServiceProviderConfig

  Returns service provider configuration including:
  - Supported authentication schemes
  - Feature support (patch, bulk, filter, etc.)
  - API documentation
  """
  def show(conn, _params) do
    config = %{
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
      documentationUri: "https://github.com/authify/authify/wiki/SCIM-Integration-Guide",
      patch: %{
        supported: true
      },
      bulk: %{
        supported: true,
        maxOperations: 1000,
        maxPayloadSize: 1_048_576
      },
      filter: %{
        supported: true,
        maxResults: 100
      },
      changePassword: %{
        supported: false
      },
      sort: %{
        supported: true
      },
      etag: %{
        supported: false
      },
      authenticationSchemes: [
        %{
          type: "oauthbearertoken",
          name: "OAuth 2.0 Bearer Token",
          description: "Authentication using OAuth 2.0 Bearer Tokens",
          specUri: "https://tools.ietf.org/html/rfc6750",
          documentationUri: "https://github.com/authify/authify/wiki/SCIM-Integration-Guide",
          primary: true
        }
      ],
      meta: %{
        resourceType: "ServiceProviderConfig",
        location: build_location_url(conn)
      }
    }

    render_scim_resource(conn, config)
  end

  defp build_location_url(conn) do
    org_slug = conn.assigns[:current_organization].slug
    "#{AuthifyWeb.Endpoint.url()}/#{org_slug}/scim/v2/ServiceProviderConfig"
  end
end
