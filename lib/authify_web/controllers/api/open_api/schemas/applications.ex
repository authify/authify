defmodule AuthifyWeb.API.OpenAPI.Schemas.Applications do
  @moduledoc """
  OpenAPI schema definitions for OAuth applications.
  """

  @doc """
  Returns the application-related schema definitions.
  """
  def build do
    %{
      "ApplicationAttributes" => application_attributes(),
      "ApplicationAttributesWithSecret" => application_attributes_with_secret(),
      "ApplicationResource" => application_resource(),
      "ApplicationResourceWithSecret" => application_resource_with_secret(),
      "ApplicationResponse" => application_response(),
      "ApplicationResponseWithSecret" => application_response_with_secret(),
      "ApplicationsCollectionResponse" => applications_collection_response(),
      "ApplicationCreateRequest" => application_create_request(),
      "ApplicationUpdateRequest" => application_update_request()
    }
  end

  @doc """
  Example applications list response data.
  """
  def applications_list_example do
    %{
      data: [
        %{
          id: "789",
          type: "application",
          attributes: %{
            name: "My Application",
            client_id: "abc123xyz",
            description: "Production OAuth app",
            redirect_uris:
              "https://app.example.com/callback\nhttps://staging.example.com/callback",
            scopes: "openid profile email",
            is_active: true,
            organization_id: 123,
            inserted_at: "2024-01-01T00:00:00Z",
            updated_at: "2024-01-15T10:30:00Z"
          },
          links: %{
            self: "/acme-corp/api/applications/789"
          }
        }
      ],
      links: %{
        self: "/acme-corp/api/applications?page=1&per_page=25",
        first: "/acme-corp/api/applications?page=1&per_page=25"
      },
      meta: %{
        total: 1,
        page: 1,
        per_page: 25
      }
    }
  end

  @doc """
  Example application with secret response (for create/regenerate operations).
  """
  def application_with_secret_example do
    %{
      data: %{
        id: "790",
        type: "application",
        attributes: %{
          name: "New Application",
          client_id: "def456uvw",
          client_secret: "super_secret_value_shown_only_once",
          description: nil,
          redirect_uris: "https://newapp.example.com/callback",
          scopes: "openid profile email",
          is_active: true,
          organization_id: 123,
          inserted_at: "2024-01-20T15:00:00Z",
          updated_at: "2024-01-20T15:00:00Z"
        },
        links: %{
          self: "/acme-corp/api/applications/790"
        }
      },
      links: %{
        self: "/acme-corp/api/applications/790"
      }
    }
  end

  @doc """
  Example regenerated secret response.
  """
  def regenerated_secret_example do
    %{
      data: %{
        id: "789",
        type: "application",
        attributes: %{
          name: "My Application",
          client_id: "abc123xyz",
          client_secret: "newly_generated_secret_value",
          description: "Production OAuth app",
          redirect_uris: "https://app.example.com/callback",
          scopes: "openid profile email",
          is_active: true,
          organization_id: 123,
          inserted_at: "2024-01-01T00:00:00Z",
          updated_at: "2024-01-20T16:00:00Z"
        },
        links: %{
          self: "/acme-corp/api/applications/789"
        }
      },
      links: %{
        self: "/acme-corp/api/applications/789"
      }
    }
  end

  defp application_attributes do
    %{
      type: "object",
      properties: %{
        name: %{type: "string", description: "Application name"},
        client_id: %{type: "string", description: "OAuth client identifier"},
        description: %{type: "string", nullable: true, description: "Application description"},
        redirect_uris: %{type: "string", description: "Newline-separated list of redirect URIs"},
        scopes: %{type: "string", description: "Space-separated list of OAuth scopes"},
        is_active: %{type: "boolean", description: "Whether the application is active"},
        organization_id: %{type: "integer", description: "Organization ID"},
        inserted_at: %{type: "string", format: "date-time", description: "Creation timestamp"},
        updated_at: %{type: "string", format: "date-time", description: "Last update timestamp"}
      }
    }
  end

  defp application_attributes_with_secret do
    %{
      allOf: [
        %{"$ref" => "#/components/schemas/ApplicationAttributes"},
        %{
          type: "object",
          properties: %{
            client_secret: %{
              type: "string",
              description: "OAuth client secret (only shown on creation and regeneration)"
            }
          }
        }
      ]
    }
  end

  defp application_resource do
    %{
      type: "object",
      properties: %{
        id: %{type: "string", description: "Application ID"},
        type: %{type: "string", enum: ["application"], description: "Resource type"},
        attributes: %{"$ref" => "#/components/schemas/ApplicationAttributes"},
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["id", "type", "attributes", "links"]
    }
  end

  defp application_resource_with_secret do
    %{
      type: "object",
      properties: %{
        id: %{type: "string", description: "Application ID"},
        type: %{type: "string", enum: ["application"], description: "Resource type"},
        attributes: %{"$ref" => "#/components/schemas/ApplicationAttributesWithSecret"},
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["id", "type", "attributes", "links"]
    }
  end

  defp application_response do
    %{
      type: "object",
      properties: %{
        data: %{"$ref" => "#/components/schemas/ApplicationResource"},
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["data", "links"]
    }
  end

  defp application_response_with_secret do
    %{
      type: "object",
      properties: %{
        data: %{"$ref" => "#/components/schemas/ApplicationResourceWithSecret"},
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["data", "links"]
    }
  end

  defp applications_collection_response do
    %{
      type: "object",
      properties: %{
        data: %{type: "array", items: %{"$ref" => "#/components/schemas/ApplicationResource"}},
        links: %{"$ref" => "#/components/schemas/CollectionLinks"},
        meta: %{"$ref" => "#/components/schemas/PaginationMeta"}
      },
      required: ["data", "links", "meta"]
    }
  end

  defp application_create_request do
    %{
      type: "object",
      properties: %{
        application: %{
          type: "object",
          properties: %{
            name: %{type: "string", minLength: 1, maxLength: 255},
            description: %{type: "string", nullable: true},
            redirect_uris: %{
              type: "string",
              description: "Newline-separated list of valid redirect URIs"
            },
            scopes: %{
              type: "string",
              default: "openid profile email",
              description: "Space-separated list of OAuth scopes"
            }
          },
          required: ["name", "redirect_uris"]
        }
      },
      required: ["application"]
    }
  end

  defp application_update_request do
    %{
      type: "object",
      properties: %{
        application: %{
          type: "object",
          properties: %{
            name: %{type: "string", minLength: 1, maxLength: 255},
            description: %{type: "string", nullable: true},
            redirect_uris: %{
              type: "string",
              description: "Newline-separated list of valid redirect URIs"
            },
            scopes: %{type: "string", description: "Space-separated list of OAuth scopes"},
            is_active: %{type: "boolean"}
          }
        }
      },
      required: ["application"]
    }
  end
end
