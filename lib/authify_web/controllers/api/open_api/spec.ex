defmodule AuthifyWeb.API.OpenAPI.Spec do
  @moduledoc """
  Main OpenAPI specification builder for Authify Management API.
  """

  import Plug.Conn, only: [get_req_header: 2]

  @doc """
  Returns the OpenAPI info section.
  """
  def info(_base_url) do
    app_version = Application.spec(:authify, :vsn) |> to_string()

    %{
      title: "Authify Management API",
      description: """
      Comprehensive REST API for managing Authify organizations, users, and OAuth applications.

      **Application Version**: #{app_version}

      ## Features
      - **HATEOAS Compliance**: All responses include hypermedia links for navigation
      - **Header-based Versioning**: Use `Accept: application/vnd.authify.v1+json`
      - **Multi-tenant**: Organization-scoped access control
      - **Pagination**: Efficient pagination with navigation links
      - **Comprehensive Error Handling**: Structured error responses with validation details

      ## Authentication
      Use Bearer token authentication with a valid API token or session-based authentication.

      ## Rate Limiting
      API endpoints are rate-limited per organization. Limits and current usage are returned in response headers.
      """,
      version: "1.0.0",
      contact: %{
        name: "Authify Support",
        url: "https://github.com/authify/authify"
      },
      license: %{
        name: "MIT",
        url: "https://opensource.org/licenses/MIT"
      }
    }
  end

  @doc """
  Returns the OpenAPI servers section.
  """
  def servers(base_url) do
    [
      %{
        url: base_url,
        description: "Current deployment"
      }
    ]
  end

  @doc """
  Returns the OpenAPI security requirements.
  """
  def security do
    [
      %{"BearerAuth" => []},
      %{"OAuth2" => []},
      %{"SessionAuth" => []}
    ]
  end

  @doc """
  Returns the OpenAPI tags section.
  """
  def tags do
    [
      %{
        name: "Organization",
        description: "Organization profile and settings management"
      },
      %{
        name: "Users",
        description: "User management and role administration"
      },
      %{
        name: "Profile",
        description: "Current user's profile management and preferences"
      },
      %{
        name: "Invitations",
        description: "User invitation management"
      },
      %{
        name: "Applications",
        description: "OAuth 2.0 application management"
      },
      %{
        name: "Groups",
        description: "Group management for organizing users and controlling application access"
      },
      %{
        name: "Certificates",
        description: "SSL/TLS certificate management for SAML and OAuth signing"
      },
      %{
        name: "SAML Providers",
        description: "SAML 2.0 service provider configuration"
      },
      %{
        name: "SCIM Clients",
        description: "SCIM 2.0 client management for outbound user and group provisioning"
      },
      %{
        name: "Audit Logs",
        description: "Organization audit log access and filtering"
      },
      %{
        name: "Authentication",
        description: "API authentication and authorization"
      }
    ]
  end

  @doc """
  Get API base URL from configuration or build from request.
  Supports X-Forwarded-Proto header for proper HTTPS detection behind proxies.
  """
  def get_api_base_url(conn) do
    # Check if API base URL is configured
    case Application.get_env(:authify, :api_base_url) do
      nil ->
        # Build from request with proper protocol detection
        scheme = get_scheme(conn)
        host = get_req_header(conn, "host") |> List.first() || "localhost:4000"
        "#{scheme}://#{host}"

      configured_url ->
        configured_url
    end
  end

  # Get the scheme (http/https) from the request
  # Checks X-Forwarded-Proto header first (set by reverse proxies)
  defp get_scheme(conn) do
    case get_req_header(conn, "x-forwarded-proto") do
      [proto | _] when proto in ["http", "https"] ->
        proto

      _ ->
        # Fall back to conn.scheme
        if conn.scheme == :https, do: "https", else: "http"
    end
  end
end
