defmodule AuthifyWeb.API.OpenAPI.Paths.Profile do
  @moduledoc """
  OpenAPI path definitions for user profile endpoints.
  """

  alias AuthifyWeb.API.OpenAPI.Schemas.Profile

  @doc """
  Returns the profile-related path definitions.
  """
  def build do
    %{
      "/{org_slug}/api/profile" => %{
        "get" => %{
          tags: ["Profile"],
          summary: "Get current user's profile",
          description: """
          Retrieve the authenticated user's own profile information.

          Returns the full user profile including email, names, username, theme preference,
          role, and account status. This endpoint always returns data for the currently
          authenticated user based on the access token.

          **Requires:** `profile:read` scope
          """,
          operationId: "getProfile",
          parameters: [
            %{
              "$ref" => "#/components/parameters/OrgSlugPath"
            }
          ],
          security: [
            %{"BearerAuth" => ["profile:read"]},
            %{"OAuth2" => ["profile:read"]},
            %{"SessionAuth" => []}
          ],
          responses: %{
            "200" => %{
              description: "Profile retrieved successfully",
              content: %{
                "application/json" => %{
                  schema: %{"$ref" => "#/components/schemas/ProfileResponse"},
                  example: Profile.profile_example()
                }
              }
            },
            "401" => %{"$ref" => "#/components/responses/UnauthorizedError"},
            "403" => %{"$ref" => "#/components/responses/ForbiddenError"}
          }
        },
        "put" => %{
          tags: ["Profile"],
          summary: "Update current user's profile",
          description: """
          Update the authenticated user's own profile information.

          Allows updating the following fields:
          - `first_name` - User's first name
          - `last_name` - User's last name
          - `username` - Username (must be unique within the organization)
          - `theme_preference` - UI theme preference (auto, light, or dark)

          Other profile fields (email, role, active status) cannot be updated through
          this endpoint and require admin access via the Users API.

          **Requires:** `profile:write` scope
          """,
          operationId: "updateProfile",
          parameters: [
            %{
              "$ref" => "#/components/parameters/OrgSlugPath"
            }
          ],
          security: [
            %{"BearerAuth" => ["profile:write"]},
            %{"OAuth2" => ["profile:write"]},
            %{"SessionAuth" => []}
          ],
          requestBody: %{
            required: true,
            content: %{
              "application/json" => %{
                schema: %{"$ref" => "#/components/schemas/ProfileUpdateRequest"},
                example: %{
                  user: %{
                    first_name: "Jane",
                    last_name: "Smith",
                    username: "jsmith",
                    theme_preference: "dark"
                  }
                }
              }
            }
          },
          responses: %{
            "200" => %{
              description: "Profile updated successfully",
              content: %{
                "application/json" => %{
                  schema: %{"$ref" => "#/components/schemas/ProfileResponse"},
                  example: Profile.profile_example()
                }
              }
            },
            "400" => %{"$ref" => "#/components/responses/BadRequestError"},
            "401" => %{"$ref" => "#/components/responses/UnauthorizedError"},
            "403" => %{"$ref" => "#/components/responses/ForbiddenError"},
            "422" => %{"$ref" => "#/components/responses/ValidationError"}
          }
        }
      }
    }
  end
end
