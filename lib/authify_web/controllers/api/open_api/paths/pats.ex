defmodule AuthifyWeb.API.OpenAPI.Paths.Pats do
  @moduledoc """
  OpenAPI path definitions for personal access token lifecycle endpoints.
  """

  alias AuthifyWeb.API.OpenAPI.Schemas.Pats

  @doc """
  Returns the personal access token path definitions.
  """
  def build do
    %{
      "/{org_slug}/api/pats" => tokens_collection(),
      "/{org_slug}/api/pats/{id}" => token_resource()
    }
  end

  defp tokens_collection do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Personal Access Tokens"],
        summary: "List personal access tokens",
        description: """
        List the authenticated user's personal access tokens.

        Organization administrators may pass the `user_id` query parameter to
        list another user's tokens. Token values are never returned by this
        endpoint; the plaintext value is only available in the create response.

        **Requires:** `profile:read`, or `users:read` when listing another user's tokens.
        """,
        operationId: "listPersonalAccessTokens",
        security: [
          %{"OAuth2" => ["profile:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "user_id",
            in: "query",
            required: false,
            description:
              "User ID whose tokens should be listed. Requires the `users:read` scope and organization administrator role.",
            schema: %{type: "integer"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Personal access tokens retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/PersonalAccessTokensCollectionResponse"}
              }
            }
          },
          "400" => %{"$ref" => "#/components/responses/BadRequest"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      },
      post: %{
        tags: ["Personal Access Tokens"],
        summary: "Create a personal access token",
        description: """
        Create a personal access token for the authenticated user.

        Organization administrators may include `user_id` in the request body
        to create a token for another user in the same organization.

        The plaintext token value is returned exactly once, in the create
        response, under `data.attributes.token`. Store it immediately; it
        cannot be retrieved again.

        When authenticated with a personal access token, the new token's scopes
        must be a subset of the authenticating token's scopes.

        **Requires:** `profile:write`, or `users:write` when creating a token for another user.
        """,
        operationId: "createPersonalAccessToken",
        security: [
          %{"OAuth2" => ["profile:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/vnd.authify.v1+json" => %{
              schema: %{"$ref" => "#/components/schemas/PersonalAccessTokenCreateRequest"},
              example: %{
                personal_access_token: %{
                  name: "CI deployment token",
                  description: "Used by the deployment pipeline",
                  scopes: ["profile:read", "profile:write"],
                  expires_at: "2027-10-20T00:00:00Z"
                }
              }
            }
          }
        },
        responses: %{
          "201" => %{
            description: "Personal access token created successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/PersonalAccessTokenResponse"},
                example: Pats.token_example(include_token: true)
              }
            }
          },
          "400" => %{"$ref" => "#/components/responses/BadRequest"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"},
          "422" => %{"$ref" => "#/components/responses/ValidationError"}
        }
      }
    }
  end

  defp token_resource do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      delete: %{
        tags: ["Personal Access Tokens"],
        summary: "Revoke a personal access token",
        description: """
        Permanently revoke a personal access token.

        Users may revoke their own tokens. Organization administrators may
        revoke tokens belonging to other users in the same organization.

        **Requires:** `profile:write`, or `users:write` when revoking another user's token.
        """,
        operationId: "revokePersonalAccessToken",
        security: [
          %{"OAuth2" => ["profile:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Personal access token ID",
            schema: %{type: "integer"}
          }
        ],
        responses: %{
          "204" => %{description: "Personal access token revoked successfully"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      }
    }
  end
end
