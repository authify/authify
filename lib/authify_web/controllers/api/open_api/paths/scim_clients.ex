defmodule AuthifyWeb.API.OpenAPI.Paths.ScimClients do
  @moduledoc """
  OpenAPI path definitions for SCIM Client endpoints.
  """

  alias AuthifyWeb.API.OpenAPI.Schemas.ScimClients

  def build do
    %{
      "/organizations/{org_slug}/scim-clients" => build_scim_clients_endpoints(),
      "/organizations/{org_slug}/scim-clients/{id}" => build_scim_client_endpoints(),
      "/organizations/{org_slug}/scim-clients/{scim_client_id}/sync" =>
        build_scim_client_sync_endpoint(),
      "/organizations/{org_slug}/scim-clients/{scim_client_id}/logs" =>
        build_scim_client_logs_endpoint()
    }
  end

  defp build_scim_clients_endpoints do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["SCIM Clients"],
        summary: "List SCIM clients",
        description:
          "Get a paginated list of SCIM clients for outbound provisioning in the organization. Requires `scim_clients:read` or `scim_clients:write` scope.",
        security: [
          %{"OAuth2" => ["scim_clients:read"]},
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
            description: "SCIM clients retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/ScimClientsCollectionResponse"},
                example: ScimClients.scim_clients_list_example()
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"}
        }
      },
      post: %{
        tags: ["SCIM Clients"],
        summary: "Create SCIM client",
        description:
          "Create a new SCIM client configuration for outbound provisioning. Requires `scim_clients:write` scope.",
        security: [
          %{"OAuth2" => ["scim_clients:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{"$ref" => "#/components/schemas/ScimClientCreateRequest"}
            }
          }
        },
        responses: %{
          "201" => %{
            description: "SCIM client created successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/ScimClientResponse"},
                example: ScimClients.scim_client_example()
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

  defp build_scim_client_endpoints do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["SCIM Clients"],
        summary: "Get SCIM client",
        description:
          "Retrieve a specific SCIM client's configuration details. Requires `scim_clients:read` or `scim_clients:write` scope.",
        security: [
          %{"OAuth2" => ["scim_clients:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "SCIM client ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "200" => %{
            description: "SCIM client retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/ScimClientResponse"},
                example: ScimClients.scim_client_example()
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      },
      put: %{
        tags: ["SCIM Clients"],
        summary: "Update SCIM client",
        description: "Update a SCIM client's configuration. Requires `scim_clients:write` scope.",
        security: [
          %{"OAuth2" => ["scim_clients:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "SCIM client ID",
            schema: %{type: "string"}
          }
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{"$ref" => "#/components/schemas/ScimClientUpdateRequest"}
            }
          }
        },
        responses: %{
          "200" => %{
            description: "SCIM client updated successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/ScimClientResponse"},
                example: ScimClients.scim_client_example()
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
        tags: ["SCIM Clients"],
        summary: "Delete SCIM client",
        description:
          "Delete a SCIM client from the organization. Requires `scim_clients:write` scope.",
        security: [
          %{"OAuth2" => ["scim_clients:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "SCIM client ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "204" => %{description: "SCIM client deleted successfully"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      }
    }
  end

  defp build_scim_client_sync_endpoint do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      post: %{
        tags: ["SCIM Clients"],
        summary: "Trigger manual sync",
        description:
          "Manually trigger a full synchronization for a SCIM client. Requires `scim_clients:write` scope.",
        security: [
          %{"OAuth2" => ["scim_clients:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "scim_client_id",
            in: "path",
            required: true,
            description: "SCIM client ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Sync triggered successfully",
            content: %{
              "application/json" => %{
                schema: %{
                  type: "object",
                  properties: %{
                    status: %{type: "string", example: "sync_triggered"},
                    message: %{type: "string", example: "Full sync initiated for SCIM client"}
                  }
                }
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

  defp build_scim_client_logs_endpoint do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["SCIM Clients"],
        summary: "Get SCIM sync logs",
        description:
          "Retrieve synchronization logs for a specific SCIM client. Requires `scim_clients:read` or `scim_clients:write` scope.",
        security: [
          %{"OAuth2" => ["scim_clients:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "scim_client_id",
            in: "path",
            required: true,
            description: "SCIM client ID",
            schema: %{type: "string"}
          },
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
            schema: %{type: "integer", minimum: 1, maximum: 100, default: 50}
          }
        ],
        responses: %{
          "200" => %{
            description: "Sync logs retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/ScimSyncLogsCollectionResponse"},
                example: ScimClients.scim_sync_logs_example()
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
