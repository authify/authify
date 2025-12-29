defmodule AuthifyWeb.API.OpenAPI.Paths.Users do
  @moduledoc """
  OpenAPI path definitions for user endpoints.
  """

  alias AuthifyWeb.API.OpenAPI.Schemas.Users

  @doc """
  Returns the user endpoint definitions.
  """
  def build do
    %{
      "/{org_slug}/api/users" => users_collection(),
      "/{org_slug}/api/users/{id}" => user_resource(),
      "/{org_slug}/api/users/{id}/role" => user_role()
    }
  end

  defp users_collection do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Users"],
        summary: "List users",
        description: "Get a paginated list of users in the organization",
        security: [
          %{"OAuth2" => ["users:read"]},
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
            description: "Users retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/UsersCollectionResponse"},
                example: Users.users_list_example()
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"}
        }
      },
      post: %{
        tags: ["Users"],
        summary: "Create user",
        description: "Create a new user in the organization",
        security: [
          %{"OAuth2" => ["users:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{"$ref" => "#/components/schemas/UserCreateRequest"},
              example: %{
                user: %{
                  email: "jane@acme.com",
                  first_name: "Jane",
                  last_name: "Smith",
                  password: "SecureP@ssw0rd!",
                  password_confirmation: "SecureP@ssw0rd!"
                }
              }
            }
          }
        },
        responses: %{
          "201" => %{
            description: "User created successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/UserResponse"}
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

  defp user_resource do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Users"],
        summary: "Get user",
        description: "Retrieve a specific user's details",
        security: [
          %{"OAuth2" => ["users:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "User ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "200" => %{
            description: "User retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/UserResponse"}
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      },
      put: %{
        tags: ["Users"],
        summary: "Update user",
        description: "Update a user's information",
        security: [
          %{"OAuth2" => ["users:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "User ID",
            schema: %{type: "string"}
          }
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{"$ref" => "#/components/schemas/UserUpdateRequest"}
            }
          }
        },
        responses: %{
          "200" => %{
            description: "User updated successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/UserResponse"}
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
        tags: ["Users"],
        summary: "Delete user",
        description: "Delete a user from the organization",
        security: [
          %{"OAuth2" => ["users:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "User ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "204" => %{description: "User deleted successfully"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      }
    }
  end

  defp user_role do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      put: %{
        tags: ["Users"],
        summary: "Update user role",
        description: "Update a user's role in the organization",
        security: [
          %{"OAuth2" => ["users:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "User ID",
            schema: %{type: "string"}
          }
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{
                type: "object",
                properties: %{
                  role: %{
                    type: "string",
                    enum: ["user", "admin"],
                    description: "New role for the user"
                  }
                },
                required: ["role"]
              },
              example: %{role: "admin"}
            }
          }
        },
        responses: %{
          "200" => %{
            description: "User role updated successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/UserResponse"}
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"},
          "422" => %{"$ref" => "#/components/responses/ValidationError"}
        }
      }
    }
  end
end
