defmodule AuthifyWeb.API.OpenAPI.Paths.Applications do
  @moduledoc """
  OpenAPI path definitions for OAuth application endpoints.
  """

  alias AuthifyWeb.API.OpenAPI.Schemas.Applications

  @doc """
  Returns the OAuth application endpoint definitions.
  """
  def build do
    %{
      "/{org_slug}/api/applications" => applications_endpoints(),
      "/{org_slug}/api/applications/{id}" => application_endpoints(),
      "/{org_slug}/api/applications/{id}/regenerate_secret" => regenerate_secret_endpoint()
    }
  end

  defp applications_endpoints do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Applications"],
        summary: "List OAuth applications",
        description: "Get a paginated list of OAuth applications in the organization",
        security: [
          %{"OAuth2" => ["applications:read"]},
          %{"OAuth2" => ["management_app:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "page",
            in: "query",
            description: "Page number (1-based)",
            schema: %{type: "integer", minimum: 1, default: 1}
          },
          %{
            name: "per_page",
            in: "query",
            description: "Number of items per page",
            schema: %{type: "integer", minimum: 1, maximum: 100, default: 25}
          }
        ],
        responses: %{
          "200" => %{
            description: "Applications retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/ApplicationsCollectionResponse"},
                example: Applications.applications_list_example()
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"}
        }
      },
      post: %{
        tags: ["Applications"],
        summary: "Create OAuth application",
        description: "Create a new OAuth application",
        security: [
          %{"OAuth2" => ["applications:write"]},
          %{"OAuth2" => ["management_app:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{"$ref" => "#/components/schemas/ApplicationCreateRequest"},
              example: %{
                application: %{
                  name: "Mobile App",
                  description: "Company mobile application",
                  redirect_uris: "com.acme.app://oauth/callback",
                  scopes: "openid profile email"
                }
              }
            }
          }
        },
        responses: %{
          "201" => %{
            description: "Application created successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/ApplicationResponseWithSecret"},
                example: Applications.application_with_secret_example()
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

  defp application_endpoints do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Applications"],
        summary: "Get OAuth application",
        description: "Retrieve a specific OAuth application's details",
        security: [
          %{"OAuth2" => ["applications:read"]},
          %{"OAuth2" => ["management_app:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Application ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Application retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/ApplicationResponse"}
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      },
      put: %{
        tags: ["Applications"],
        summary: "Update OAuth application",
        description: "Update an OAuth application's configuration",
        security: [
          %{"OAuth2" => ["applications:read"]},
          %{"OAuth2" => ["management_app:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Application ID",
            schema: %{type: "string"}
          }
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{"$ref" => "#/components/schemas/ApplicationUpdateRequest"}
            }
          }
        },
        responses: %{
          "200" => %{
            description: "Application updated successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/ApplicationResponse"}
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"},
          "422" => %{"$ref" => "#/components/responses/ValidationError"}
        }
      },
      delete: %{
        tags: ["Applications"],
        summary: "Delete OAuth application",
        description: "Delete an OAuth application",
        security: [
          %{"OAuth2" => ["applications:write"]},
          %{"OAuth2" => ["management_app:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Application ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "204" => %{description: "Application deleted successfully"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      }
    }
  end

  defp regenerate_secret_endpoint do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      post: %{
        tags: ["Applications"],
        summary: "Regenerate client secret",
        description: "Generate a new client secret for the OAuth application",
        security: [
          %{"OAuth2" => ["applications:write"]},
          %{"OAuth2" => ["management_app:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Application ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Client secret regenerated successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/ApplicationResponseWithSecret"},
                example: Applications.regenerated_secret_example()
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      }
    }
  end
end
