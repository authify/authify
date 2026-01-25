defmodule AuthifyWeb.API.OpenAPI.Schemas.Organizations do
  @moduledoc """
  OpenAPI schema definitions for organizations and configuration.
  """

  @doc """
  Returns the organization-related schema definitions.
  """
  def build do
    %{
      "OrganizationAttributes" => organization_attributes(),
      "OrganizationResource" => organization_resource(),
      "OrganizationResponse" => organization_response(),
      "ConfigurationResponse" => configuration_response(),
      "ConfigurationUpdateRequest" => configuration_update_request()
    }
  end

  @doc """
  Example organization response data.
  """
  def organization_example do
    %{
      data: %{
        id: "123",
        type: "organization",
        attributes: %{
          name: "Acme Corp",
          slug: "acme-corp",
          active: true,
          inserted_at: "2024-01-01T00:00:00Z",
          updated_at: "2024-01-01T00:00:00Z"
        },
        links: %{
          self: "/acme-corp/api/organization"
        }
      },
      links: %{
        self: "/acme-corp/api/organization"
      }
    }
  end

  defp organization_attributes do
    %{
      type: "object",
      properties: %{
        name: %{type: "string", description: "Organization name"},
        slug: %{type: "string", description: "Organization slug (URL-friendly identifier)"},
        active: %{type: "boolean", description: "Whether the organization is active"},
        inserted_at: %{type: "string", format: "date-time", description: "Creation timestamp"},
        updated_at: %{type: "string", format: "date-time", description: "Last update timestamp"}
      }
    }
  end

  defp organization_resource do
    %{
      type: "object",
      properties: %{
        id: %{type: "string", description: "Organization ID"},
        type: %{type: "string", enum: ["organization"], description: "Resource type"},
        attributes: %{"$ref" => "#/components/schemas/OrganizationAttributes"},
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["id", "type", "attributes", "links"]
    }
  end

  defp organization_response do
    %{
      type: "object",
      properties: %{
        data: %{"$ref" => "#/components/schemas/OrganizationResource"},
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["data", "links"]
    }
  end

  defp configuration_response do
    %{
      type: "object",
      properties: %{
        data: %{
          type: "object",
          properties: %{
            id: %{type: "string", format: "uuid", description: "Organization ID"},
            type: %{type: "string", example: "configuration"},
            attributes: %{
              type: "object",
              properties: %{
                id: %{type: "integer", description: "Organization ID"},
                schema_name: %{
                  type: "string",
                  enum: ["global", "organization"],
                  description:
                    "Schema name: 'global' for authify-global org, 'organization' for regular orgs"
                },
                settings: %{
                  type: "object",
                  description: "Configuration settings (varies by schema)",
                  example: %{
                    allow_organization_registration: false,
                    site_name: "Authify",
                    support_email: "support@example.com"
                  }
                },
                updated_at: %{
                  type: "string",
                  format: "date-time",
                  description: "Last update timestamp"
                }
              },
              required: ["id", "schema_name", "settings"]
            }
          }
        },
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["data", "links"]
    }
  end

  defp configuration_update_request do
    %{
      type: "object",
      properties: %{
        settings: %{
          type: "object",
          description: "Configuration settings to update (varies by organization schema)",
          oneOf: [
            %{
              description: "Global settings (authify-global organization)",
              properties: %{
                allow_organization_registration: %{
                  type: "boolean",
                  description: "Allow new organizations to self-register"
                },
                site_name: %{type: "string", description: "Name of the Authify instance"},
                support_email: %{
                  type: "string",
                  format: "email",
                  description: "Support contact email"
                }
              }
            },
            %{
              description: "Organization settings (regular organizations)",
              properties: %{
                allow_invitations: %{
                  type: "boolean",
                  description: "Allow admins to invite new users"
                },
                allow_saml: %{type: "boolean", description: "Enable SAML 2.0 identity provider"},
                allow_oauth: %{
                  type: "boolean",
                  description: "Enable OAuth2/OIDC identity provider"
                },
                allow_webauthn: %{
                  type: "boolean",
                  description:
                    "Enable WebAuthn/FIDO2 authentication (security keys, passkeys, biometrics)"
                },
                scim_inbound_provisioning_enabled: %{
                  type: "boolean",
                  description:
                    "Enable SCIM 2.0 Service Provider endpoints - allows external systems to provision users/groups into this organization"
                },
                description: %{
                  type: "string",
                  description: "Organization description (max 1000 chars)"
                },
                website_url: %{
                  type: "string",
                  format: "uri",
                  description: "Organization website URL"
                },
                contact_email: %{
                  type: "string",
                  format: "email",
                  description: "Organization contact email"
                },
                logo_url: %{type: "string", format: "uri", description: "Organization logo URL"}
              }
            }
          ]
        }
      },
      required: ["settings"]
    }
  end
end
