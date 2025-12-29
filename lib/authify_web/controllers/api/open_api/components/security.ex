defmodule AuthifyWeb.API.OpenAPI.Components.Security do
  @moduledoc """
  OpenAPI security scheme definitions for Authify Management API.
  """

  @doc """
  Returns the security schemes for the OpenAPI specification.
  """
  def build(base_url) do
    %{
      "BearerAuth" => %{
        type: "http",
        scheme: "bearer",
        bearerFormat: "JWT",
        description:
          "OAuth2 Bearer token or Personal Access Token authentication. Include token in Authorization header as 'Bearer <token>'."
      },
      "OAuth2" => %{
        type: "oauth2",
        description:
          "OAuth2 authentication with granular scopes for API access. Use the Client Credentials flow with Management API applications to programmatically access the API with client_id and client_secret.",
        flows: %{
          authorizationCode: %{
            authorizationUrl: "#{base_url}/{org_slug}/oauth/authorize",
            tokenUrl: "#{base_url}/{org_slug}/oauth/token",
            scopes: scopes()
          },
          clientCredentials: %{
            tokenUrl: "#{base_url}/{org_slug}/oauth/token",
            scopes: scopes()
          }
        }
      },
      "SessionAuth" => %{
        type: "apiKey",
        in: "cookie",
        name: "_authify_session",
        description:
          "Session-based authentication for web browsers. Automatically grants all API scopes."
      }
    }
  end

  defp scopes do
    %{
      "applications:read" => "Read OAuth2 applications",
      "applications:write" => "Manage OAuth2 applications",
      "certificates:read" => "Read certificates",
      "certificates:write" => "Manage certificates",
      "groups:read" => "Read groups and memberships",
      "groups:write" => "Manage groups and memberships",
      "invitations:read" => "Read invitations",
      "invitations:write" => "Manage invitations",
      "management_app:read" => "Read Management API applications",
      "management_app:write" => "Manage Management API applications",
      "organizations:read" => "Read organization configuration",
      "organizations:write" => "Manage organization configuration",
      "profile:read" => "Read current user's profile",
      "profile:write" => "Update current user's profile",
      "saml:read" => "Read SAML service providers",
      "saml:write" => "Manage SAML service providers",
      "users:read" => "Read users",
      "users:write" => "Manage users"
    }
  end
end
