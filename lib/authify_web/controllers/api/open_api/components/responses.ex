defmodule AuthifyWeb.API.OpenAPI.Components.Responses do
  @moduledoc """
  OpenAPI standard response definitions for Authify Management API.
  """

  @doc """
  Returns the standard response definitions for the OpenAPI specification.
  """
  def build(base_url) do
    %{
      "BadRequest" => %{
        description: "Bad request - invalid request format",
        content: %{
          "application/vnd.authify.v1+json" => %{
            schema: %{"$ref" => "#/components/schemas/ErrorResponse"},
            example: %{
              error: %{
                type: "bad_request",
                message: "Invalid request format"
              },
              links: %{
                documentation: "#{base_url}/developers/errors"
              }
            }
          }
        }
      },
      "Unauthorized" => %{
        description: "Unauthorized - authentication required",
        content: %{
          "application/vnd.authify.v1+json" => %{
            schema: %{"$ref" => "#/components/schemas/ErrorResponse"},
            example: %{
              error: %{
                type: "unauthorized",
                message: "Authentication required"
              },
              links: %{
                documentation: "#{base_url}/developers/errors"
              }
            }
          }
        }
      },
      "Forbidden" => %{
        description: "Forbidden - insufficient permissions",
        content: %{
          "application/vnd.authify.v1+json" => %{
            schema: %{"$ref" => "#/components/schemas/ErrorResponse"},
            example: %{
              error: %{
                type: "forbidden",
                message: "Insufficient permissions"
              },
              links: %{
                documentation: "#{base_url}/developers/errors"
              }
            }
          }
        }
      },
      "NotFound" => %{
        description: "Not found - resource not found",
        content: %{
          "application/vnd.authify.v1+json" => %{
            schema: %{"$ref" => "#/components/schemas/ErrorResponse"},
            example: %{
              error: %{
                type: "resource_not_found",
                message: "Resource not found in organization"
              },
              links: %{
                documentation: "#{base_url}/developers/errors"
              }
            }
          }
        }
      },
      "ValidationError" => %{
        description: "Validation error - request data failed validation",
        content: %{
          "application/vnd.authify.v1+json" => %{
            schema: %{"$ref" => "#/components/schemas/ErrorResponse"},
            example: %{
              error: %{
                type: "validation_failed",
                message: "The request data failed validation",
                details: %{
                  email: ["is required"],
                  password: ["must be at least 8 characters"]
                }
              },
              links: %{
                documentation: "#{base_url}/developers/errors"
              }
            }
          }
        }
      }
    }
  end
end
