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
      # OAuth/OIDC Scopes
      "openid" => "OpenID Connect authentication",
      "profile" => "Read user profile information (name, username, etc.)",
      "email" => "Read user email address",
      # Management API Scopes - Applications
      "applications:read" => "Read OAuth2 applications",
      "applications:write" => "Manage OAuth2 applications",
      "application_groups:read" => "Read application groups",
      "application_groups:write" => "Manage application groups",
      "management_app:read" => "Read Management API applications",
      "management_app:write" => "Manage Management API applications",
      # Management API Scopes - Users & Groups
      "users:read" => "Read users in organization",
      "users:write" => "Manage users in organization",
      "groups:read" => "Read groups and memberships",
      "groups:write" => "Manage groups and memberships",
      # Management API Scopes - Invitations
      "invitations:read" => "Read invitations",
      "invitations:write" => "Manage invitations",
      # Management API Scopes - SAML
      "saml:read" => "Read SAML service providers",
      "saml:write" => "Manage SAML service providers",
      # Management API Scopes - Certificates
      "certificates:read" => "Read certificates",
      "certificates:write" => "Manage certificates",
      # Management API Scopes - Organization
      "organizations:read" => "Read organization configuration and settings",
      "organizations:write" => "Manage organization configuration and settings",
      # Management API Scopes - Audit
      "audit_logs:read" => "Read audit logs for organization",
      # Personal Access Token Scopes
      "profile:read" => "Read your own profile information",
      "profile:write" => "Update your own profile information",
      # SCIM 2.0 Provisioning Scopes
      "scim:read" => "Read all SCIM resources (users and groups)",
      "scim:write" => "Manage all SCIM resources (users and groups)",
      "scim:users:read" => "Read SCIM user resources",
      "scim:users:write" => "Manage SCIM user resources",
      "scim:groups:read" => "Read SCIM group resources",
      "scim:groups:write" => "Manage SCIM group resources",
      "scim:me" => "Read your own SCIM resource (self-service)",
      "scim:me:write" => "Update your own SCIM resource (self-service)"
    }
  end
end
