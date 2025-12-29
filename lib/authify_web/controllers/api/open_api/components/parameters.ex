defmodule AuthifyWeb.API.OpenAPI.Components.Parameters do
  @moduledoc """
  OpenAPI parameter definitions for Authify Management API.
  """

  @doc """
  Returns the common parameter definitions for the OpenAPI specification.
  """
  def build do
    %{
      "OrgSlug" => %{
        name: "org_slug",
        in: "path",
        required: true,
        description: "Organization slug identifier",
        schema: %{
          type: "string",
          pattern: "^[a-z0-9-]+$",
          example: "my-organization"
        }
      },
      "AcceptHeader" => %{
        name: "Accept",
        in: "header",
        required: true,
        description:
          "API version negotiation. Use 'application/vnd.authify.v1+json' for versioned responses or 'application/json' for default version.",
        schema: %{
          type: "string",
          enum: ["application/vnd.authify.v1+json", "application/json"],
          default: "application/vnd.authify.v1+json"
        }
      }
    }
  end
end
