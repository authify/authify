defmodule AuthifyWeb.API.OpenAPI.Schemas.Profile do
  @moduledoc """
  OpenAPI schema definitions for user profile endpoints.
  """

  @doc """
  Returns the profile-related schema definitions.
  """
  def build do
    %{
      "ProfileAttributes" => profile_attributes(),
      "ProfileResource" => profile_resource(),
      "ProfileResponse" => profile_response(),
      "ProfileUpdateRequest" => profile_update_request()
    }
  end

  @doc """
  Example profile response data.
  """
  def profile_example do
    %{
      data: %{
        id: "42",
        type: "user",
        attributes: %{
          primary_email: "user@example.com",
          emails: [
            %{
              value: "user@example.com",
              type: "work",
              primary: true,
              verified_at: "2024-01-15T10:00:00Z"
            }
          ],
          first_name: "Jane",
          last_name: "Smith",
          username: "jsmith",
          role: "user",
          active: true,
          theme_preference: "dark",
          organization_id: 123,
          inserted_at: "2024-01-01T00:00:00Z",
          updated_at: "2024-01-15T10:00:00Z"
        },
        links: %{
          self: "/acme-corp/api/profile"
        }
      },
      links: %{
        self: "/acme-corp/api/profile"
      }
    }
  end

  defp profile_attributes do
    %{
      type: "object",
      properties: %{
        primary_email: %{type: "string", format: "email", description: "Primary email address"},
        emails: %{
          type: "array",
          description: "List of user email addresses",
          items: %{
            type: "object",
            properties: %{
              value: %{type: "string", format: "email"},
              type: %{type: "string", nullable: true},
              primary: %{type: "boolean"},
              verified_at: %{
                type: "string",
                format: "date-time",
                nullable: true,
                description: "Timestamp when the email was verified"
              }
            },
            required: ["value"]
          }
        },
        first_name: %{type: "string", nullable: true, description: "First name"},
        last_name: %{type: "string", nullable: true, description: "Last name"},
        username: %{
          type: "string",
          nullable: true,
          description: "Username (unique within organization)"
        },
        role: %{
          type: "string",
          enum: ["user", "admin"],
          description: "User's role in the organization"
        },
        active: %{type: "boolean", description: "Whether the user account is active"},
        theme_preference: %{
          type: "string",
          enum: ["auto", "light", "dark"],
          default: "auto",
          description: "User's theme preference"
        },
        avatar_url: %{
          type: "string",
          format: "uri",
          nullable: true,
          description: "Custom avatar URL. Falls back to Gravatar when absent."
        },
        locale: %{
          type: "string",
          nullable: true,
          description: "Preferred locale (BCP 47, e.g. en-US)"
        },
        zoneinfo: %{
          type: "string",
          nullable: true,
          description: "IANA timezone identifier (e.g. America/New_York)"
        },
        phone_number: %{
          type: "string",
          nullable: true,
          description: "Phone number"
        },
        phone_number_verified: %{
          type: "boolean",
          default: false,
          description: "Whether the phone number has been verified"
        },
        website: %{
          type: "string",
          format: "uri",
          nullable: true,
          description: "Personal or professional website URL"
        },
        team: %{
          type: "string",
          nullable: true,
          description: "Team or department (admin-managed)"
        },
        title: %{
          type: "string",
          nullable: true,
          description: "Job title (admin-managed)"
        },
        organization_id: %{type: "integer", description: "Organization ID"},
        inserted_at: %{type: "string", format: "date-time", description: "Creation timestamp"},
        updated_at: %{type: "string", format: "date-time", description: "Last update timestamp"}
      },
      required: ["primary_email", "role", "active", "organization_id"]
    }
  end

  defp profile_resource do
    %{
      type: "object",
      properties: %{
        id: %{type: "string", description: "User ID"},
        type: %{type: "string", enum: ["user"], description: "Resource type"},
        attributes: %{"$ref" => "#/components/schemas/ProfileAttributes"},
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["id", "type", "attributes", "links"]
    }
  end

  defp profile_response do
    %{
      type: "object",
      properties: %{
        data: %{"$ref" => "#/components/schemas/ProfileResource"},
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["data", "links"]
    }
  end

  defp profile_update_request do
    %{
      type: "object",
      properties: %{
        user: %{
          type: "object",
          properties: %{
            first_name: %{type: "string", description: "First name"},
            last_name: %{type: "string", description: "Last name"},
            username: %{type: "string", description: "Username (unique within organization)"},
            theme_preference: %{
              type: "string",
              enum: ["auto", "light", "dark"],
              description: "Theme preference"
            },
            avatar_url: %{
              type: "string",
              format: "uri",
              description: "Custom avatar URL (must start with http:// or https://)"
            },
            locale: %{type: "string", description: "Preferred locale (e.g. en-US)"},
            zoneinfo: %{
              type: "string",
              description: "IANA timezone identifier (e.g. America/New_York)"
            },
            phone_number: %{type: "string", description: "Phone number"},
            website: %{
              type: "string",
              format: "uri",
              description: "Personal or professional website URL"
            }
          }
        }
      },
      required: ["user"]
    }
  end
end
