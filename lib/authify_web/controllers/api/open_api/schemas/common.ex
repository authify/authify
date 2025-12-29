defmodule AuthifyWeb.API.OpenAPI.Schemas.Common do
  @moduledoc """
  Common OpenAPI schema definitions shared across resources.
  """

  @doc """
  Returns the common schema definitions (links, pagination, errors).
  """
  def build do
    %{
      "ResourceLinks" => resource_links(),
      "CollectionLinks" => collection_links(),
      "PaginationMeta" => pagination_meta(),
      "ErrorResponse" => error_response()
    }
  end

  defp resource_links do
    %{
      type: "object",
      description: "Links for individual resource responses",
      properties: %{
        self: %{type: "string", format: "uri", description: "Link to the current resource"}
      },
      required: ["self"]
    }
  end

  defp collection_links do
    %{
      type: "object",
      description: "Links for collection/list responses with pagination",
      properties: %{
        self: %{type: "string", format: "uri", description: "Link to the current page"},
        first: %{type: "string", format: "uri", description: "Link to the first page"},
        next: %{
          type: "string",
          format: "uri",
          description: "Link to the next page (present if not on last page)"
        },
        prev: %{
          type: "string",
          format: "uri",
          description: "Link to the previous page (present if not on first page)"
        },
        last: %{
          type: "string",
          format: "uri",
          description: "Link to the last page (present when total is known)"
        }
      },
      required: ["self", "first"]
    }
  end

  defp pagination_meta do
    %{
      type: "object",
      properties: %{
        total: %{type: "integer", description: "Total number of items"},
        page: %{type: "integer", description: "Current page number"},
        per_page: %{type: "integer", description: "Number of items per page"}
      },
      required: ["total", "page", "per_page"]
    }
  end

  defp error_response do
    %{
      type: "object",
      description: "Standard error response structure",
      properties: %{
        error: %{
          type: "object",
          properties: %{
            type: %{
              type: "string",
              description: "Error type identifier",
              enum: [
                "bad_request",
                "unauthorized",
                "forbidden",
                "resource_not_found",
                "validation_failed",
                "internal_server_error"
              ]
            },
            message: %{
              type: "string",
              description: "Human-readable error message"
            },
            details: %{
              type: "object",
              description: "Additional error details (e.g., validation errors)",
              additionalProperties: %{
                type: "array",
                items: %{type: "string"}
              }
            }
          },
          required: ["type", "message"]
        },
        links: %{
          type: "object",
          properties: %{
            documentation: %{
              type: "string",
              format: "uri",
              description: "Link to error documentation"
            }
          }
        }
      },
      required: ["error"]
    }
  end
end
