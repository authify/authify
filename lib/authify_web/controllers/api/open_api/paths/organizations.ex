defmodule AuthifyWeb.API.OpenAPI.Paths.Organizations do
  @moduledoc """
  OpenAPI path definitions for organization and configuration endpoints.
  """

  alias AuthifyWeb.API.OpenAPI.Schemas.Organizations

  @doc """
  Returns the organization and configuration endpoint definitions.
  """
  def build do
    %{
      "/{org_slug}/api/organization" => organization_endpoint(),
      "/{org_slug}/api/organization/configuration" => configuration_endpoint()
    }
  end

  defp organization_endpoint do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Organization"],
        summary: "Get organization profile",
        description:
          "Retrieve the current organization's basic profile (name, slug, active status). For full configuration including branding and feature toggles, use /organization/configuration",
        security: [
          %{"OAuth2" => ["organizations:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        responses: %{
          "200" => %{
            description: "Organization profile retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/OrganizationResponse"},
                example: Organizations.organization_example()
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"}
        }
      }
    }
  end

  defp configuration_endpoint do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Organization"],
        summary: "Get organization configuration",
        description:
          "Retrieve organization configuration settings. For authify-global organization, returns global settings (allow_organization_registration, site_name, support_email). For regular organizations, returns organization-specific settings (allow_invitations, allow_saml, allow_oauth, description, website_url, contact_email, logo_url).",
        security: [
          %{"OAuth2" => ["organizations:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        responses: %{
          "200" => %{
            description: "Configuration retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/ConfigurationResponse"}
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"}
        }
      },
      put: %{
        tags: ["Organization"],
        summary: "Update organization configuration",
        description:
          "Update organization configuration settings. Settings vary by organization: Global settings for authify-global (allow_organization_registration, site_name, support_email), Organization settings for regular orgs (allow_invitations, allow_saml, allow_oauth, description, website_url, contact_email, logo_url).",
        security: [
          %{"OAuth2" => ["organizations:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{"$ref" => "#/components/schemas/ConfigurationUpdateRequest"},
              examples: %{
                global: %{
                  summary: "Update global settings (authify-global org)",
                  value: %{
                    settings: %{
                      allow_organization_registration: true,
                      site_name: "My Authify Instance",
                      support_email: "support@example.com"
                    }
                  }
                },
                organization: %{
                  summary: "Update organization settings (regular org)",
                  value: %{
                    settings: %{
                      allow_invitations: true,
                      allow_saml: true,
                      allow_oauth: true,
                      description: "Leading technology company",
                      website_url: "https://acme.com",
                      contact_email: "info@acme.com",
                      logo_url: "https://acme.com/logo.png"
                    }
                  }
                }
              }
            }
          }
        },
        responses: %{
          "200" => %{
            description: "Configuration updated successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/ConfigurationResponse"}
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "422" => %{"$ref" => "#/components/responses/ValidationError"}
        }
      }
    }
  end
end
