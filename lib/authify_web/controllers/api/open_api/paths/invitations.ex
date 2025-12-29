defmodule AuthifyWeb.API.OpenAPI.Paths.Invitations do
  @moduledoc """
  OpenAPI path definitions for invitation endpoints.
  """

  alias AuthifyWeb.API.OpenAPI.Schemas.Invitations

  @doc """
  Returns the invitation endpoint definitions.
  """
  def build do
    %{
      "/{org_slug}/api/invitations" => invitations_collection(),
      "/{org_slug}/api/invitations/{id}" => invitation_resource()
    }
  end

  defp invitations_collection do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Invitations"],
        summary: "List invitations",
        description:
          "Get a paginated list of invitations in the organization with optional status filtering",
        security: [
          %{"OAuth2" => ["invitations:read"]},
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
          },
          %{
            name: "status",
            in: "query",
            description: "Filter invitations by status",
            schema: %{type: "string", enum: ["pending", "accepted", "expired"]}
          }
        ],
        responses: %{
          "200" => %{
            description: "Invitations retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/InvitationsCollectionResponse"},
                example: Invitations.invitations_list_example()
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"}
        }
      },
      post: %{
        tags: ["Invitations"],
        summary: "Create invitation",
        description: "Create a new invitation for a user to join the organization",
        security: [
          %{"OAuth2" => ["invitations:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{"$ref" => "#/components/schemas/InvitationCreateRequest"},
              example: %{
                invitation: %{
                  email: "newuser@example.com",
                  role: "user"
                }
              }
            }
          }
        },
        responses: %{
          "201" => %{
            description: "Invitation created successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/InvitationResponse"},
                example: Invitations.invitation_create_example()
              }
            }
          },
          "400" => %{"$ref" => "#/components/responses/BadRequest"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "422" => %{"$ref" => "#/components/responses/ValidationError"}
        }
      }
    }
  end

  defp invitation_resource do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Invitations"],
        summary: "Get invitation",
        description: "Retrieve a specific invitation's details",
        security: [
          %{"OAuth2" => ["invitations:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Invitation ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Invitation retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/InvitationResponse"}
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      },
      put: %{
        tags: ["Invitations"],
        summary: "Update invitation",
        description: "Update an invitation's properties",
        security: [
          %{"OAuth2" => ["invitations:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Invitation ID",
            schema: %{type: "string"}
          }
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{"$ref" => "#/components/schemas/InvitationUpdateRequest"},
              example: %{
                invitation: %{
                  role: "admin"
                }
              }
            }
          }
        },
        responses: %{
          "200" => %{
            description: "Invitation updated successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/InvitationResponse"}
              }
            }
          },
          "400" => %{"$ref" => "#/components/responses/BadRequest"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"},
          "422" => %{"$ref" => "#/components/responses/ValidationError"}
        }
      },
      delete: %{
        tags: ["Invitations"],
        summary: "Delete invitation",
        description: "Delete/cancel an invitation",
        security: [
          %{"OAuth2" => ["invitations:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Invitation ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "204" => %{description: "Invitation deleted successfully"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      }
    }
  end
end
