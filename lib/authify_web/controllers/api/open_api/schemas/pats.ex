defmodule AuthifyWeb.API.OpenAPI.Schemas.Pats do
  @moduledoc """
  OpenAPI schema definitions for personal access tokens.
  """

  @doc """
  Returns the personal access token schema definitions.
  """
  def build do
    %{
      "PersonalAccessTokenAttributes" => token_attributes(),
      "PersonalAccessTokenResource" => token_resource(),
      "PersonalAccessTokenResponse" => token_response(),
      "PersonalAccessTokensCollectionResponse" => tokens_collection_response(),
      "PersonalAccessTokenCreateRequest" => token_create_request()
    }
  end

  @doc """
  Example personal access token response data.

  Pass `include_token: true` for the create response, where the plaintext token
  value is returned exactly once.
  """
  def token_example(opts \\ []) do
    attributes = %{
      user_id: 42,
      organization_id: 123,
      name: "CI deployment token",
      description: "Used by the deployment pipeline",
      scopes: ["profile:read", "profile:write"],
      expires_at: "2027-10-20T00:00:00Z",
      last_used_at: nil,
      is_active: true,
      inserted_at: "2026-10-20T00:00:00Z",
      updated_at: "2026-10-20T00:00:00Z"
    }

    attributes =
      if opts[:include_token] do
        Map.put(attributes, :token, "authify_pat_9xQ2...")
      else
        attributes
      end

    %{
      data: %{
        id: "17",
        type: "personal_access_token",
        attributes: attributes,
        links: %{
          self: "/acme-corp/api/pats/17"
        }
      },
      links: %{
        self: "/acme-corp/api/pats/17"
      }
    }
  end

  defp token_attributes do
    %{
      type: "object",
      properties: %{
        user_id: %{type: "integer", description: "ID of the user the token belongs to"},
        organization_id: %{
          type: "integer",
          description: "ID of the organization the token belongs to"
        },
        name: %{type: "string", description: "Human-readable token name"},
        description: %{
          type: "string",
          nullable: true,
          description: "Optional token description"
        },
        scopes: %{
          type: "array",
          description: "Scopes granted to the token",
          items: %{type: "string"}
        },
        expires_at: %{
          type: "string",
          format: "date-time",
          nullable: true,
          description: "Token expiration timestamp"
        },
        last_used_at: %{
          type: "string",
          format: "date-time",
          nullable: true,
          description: "Timestamp of the last authenticated request"
        },
        is_active: %{type: "boolean", description: "Whether the token is active"},
        token: %{
          type: "string",
          nullable: true,
          description:
            "Plaintext token value. Returned exactly once, in the create response. Never present in list responses."
        },
        inserted_at: %{type: "string", format: "date-time", description: "Creation timestamp"},
        updated_at: %{type: "string", format: "date-time", description: "Last update timestamp"}
      },
      required: ["user_id", "organization_id", "name", "scopes", "is_active"]
    }
  end

  defp token_resource do
    %{
      type: "object",
      properties: %{
        id: %{type: "string", description: "Personal access token ID"},
        type: %{
          type: "string",
          enum: ["personal_access_token"],
          description: "Resource type"
        },
        attributes: %{"$ref" => "#/components/schemas/PersonalAccessTokenAttributes"},
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["id", "type", "attributes", "links"]
    }
  end

  defp token_response do
    %{
      type: "object",
      properties: %{
        data: %{"$ref" => "#/components/schemas/PersonalAccessTokenResource"},
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["data", "links"]
    }
  end

  defp tokens_collection_response do
    %{
      type: "object",
      properties: %{
        data: %{
          type: "array",
          items: %{"$ref" => "#/components/schemas/PersonalAccessTokenResource"}
        },
        links: %{"$ref" => "#/components/schemas/CollectionLinks"},
        meta: %{"$ref" => "#/components/schemas/PaginationMeta"}
      },
      required: ["data", "links", "meta"]
    }
  end

  defp token_create_request do
    %{
      type: "object",
      properties: %{
        personal_access_token: %{
          type: "object",
          properties: %{
            name: %{
              type: "string",
              minLength: 1,
              maxLength: 100,
              description: "Human-readable token name"
            },
            description: %{
              type: "string",
              maxLength: 500,
              nullable: true,
              description: "Optional token description"
            },
            scopes: %{
              type: "array",
              description: "Scopes to grant to the token",
              items: %{type: "string"}
            },
            expires_at: %{
              type: "string",
              format: "date-time",
              nullable: true,
              description:
                "Expiration timestamp. Defaults to one year from creation when omitted."
            },
            user_id: %{
              type: "integer",
              nullable: true,
              description:
                "Target user ID. Only organization administrators may create tokens for another user."
            }
          },
          required: ["name", "scopes"]
        }
      },
      required: ["personal_access_token"]
    }
  end
end
