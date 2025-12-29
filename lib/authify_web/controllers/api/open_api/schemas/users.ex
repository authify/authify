defmodule AuthifyWeb.API.OpenAPI.Schemas.Users do
  @moduledoc """
  OpenAPI schema definitions for users.
  """

  @doc """
  Returns the user-related schema definitions.
  """
  def build do
    %{
      "UserAttributes" => user_attributes(),
      "UserResource" => user_resource(),
      "UserResponse" => user_response(),
      "UsersCollectionResponse" => users_collection_response(),
      "UserCreateRequest" => user_create_request(),
      "UserUpdateRequest" => user_update_request()
    }
  end

  @doc """
  Example users list response data.
  """
  def users_list_example do
    %{
      data: [
        %{
          id: "456",
          type: "user",
          attributes: %{
            email: "john@acme.com",
            first_name: "John",
            last_name: "Doe",
            active: true,
            email_confirmed_at: "2024-01-01T00:00:00Z",
            inserted_at: "2024-01-01T00:00:00Z",
            updated_at: "2024-01-01T00:00:00Z"
          },
          links: %{
            self: "/acme-corp/api/users/456"
          }
        }
      ],
      links: %{
        self: "/acme-corp/api/users?page=1&per_page=25",
        first: "/acme-corp/api/users?page=1&per_page=25",
        next: "/acme-corp/api/users?page=2&per_page=25",
        last: "/acme-corp/api/users?page=10&per_page=25"
      },
      meta: %{
        total: 250,
        page: 1,
        per_page: 25
      }
    }
  end

  defp user_attributes do
    %{
      type: "object",
      properties: %{
        email: %{type: "string", format: "email", description: "User email address"},
        first_name: %{type: "string", nullable: true, description: "User first name"},
        last_name: %{type: "string", nullable: true, description: "User last name"},
        active: %{type: "boolean", description: "Whether the user is active"},
        email_confirmed_at: %{
          type: "string",
          format: "date-time",
          nullable: true,
          description: "Email confirmation timestamp"
        },
        inserted_at: %{type: "string", format: "date-time", description: "Creation timestamp"},
        updated_at: %{type: "string", format: "date-time", description: "Last update timestamp"}
      }
    }
  end

  defp user_resource do
    %{
      type: "object",
      properties: %{
        id: %{type: "string", description: "User ID"},
        type: %{type: "string", enum: ["user"], description: "Resource type"},
        attributes: %{"$ref" => "#/components/schemas/UserAttributes"},
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["id", "type", "attributes", "links"]
    }
  end

  defp user_response do
    %{
      type: "object",
      properties: %{
        data: %{"$ref" => "#/components/schemas/UserResource"},
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["data", "links"]
    }
  end

  defp users_collection_response do
    %{
      type: "object",
      properties: %{
        data: %{type: "array", items: %{"$ref" => "#/components/schemas/UserResource"}},
        links: %{"$ref" => "#/components/schemas/CollectionLinks"},
        meta: %{"$ref" => "#/components/schemas/PaginationMeta"}
      },
      required: ["data", "links", "meta"]
    }
  end

  defp user_create_request do
    %{
      type: "object",
      properties: %{
        user: %{
          type: "object",
          properties: %{
            email: %{type: "string", format: "email"},
            first_name: %{type: "string"},
            last_name: %{type: "string"},
            password: %{
              type: "string",
              minLength: 8,
              description: "Must contain uppercase, lowercase, number, and special character"
            },
            password_confirmation: %{type: "string", description: "Must match password"}
          },
          required: ["email", "password", "password_confirmation"]
        }
      },
      required: ["user"]
    }
  end

  defp user_update_request do
    %{
      type: "object",
      properties: %{
        user: %{
          type: "object",
          properties: %{
            first_name: %{type: "string"},
            last_name: %{type: "string"},
            active: %{type: "boolean"}
          }
        }
      },
      required: ["user"]
    }
  end
end
