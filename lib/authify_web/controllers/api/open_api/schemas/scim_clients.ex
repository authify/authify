defmodule AuthifyWeb.API.OpenAPI.Schemas.ScimClients do
  @moduledoc """
  OpenAPI schema definitions for SCIM clients.
  """

  @doc """
  Returns the SCIM client-related schema definitions.
  """
  def build do
    %{
      "ScimClientAttributes" => scim_client_attributes(),
      "ScimClientResource" => scim_client_resource(),
      "ScimClientResponse" => scim_client_response(),
      "ScimClientsCollectionResponse" => scim_clients_collection_response(),
      "ScimClientCreateRequest" => scim_client_create_request(),
      "ScimClientUpdateRequest" => scim_client_update_request(),
      "ScimSyncLogAttributes" => scim_sync_log_attributes(),
      "ScimSyncLogResource" => scim_sync_log_resource(),
      "ScimSyncLogsCollectionResponse" => scim_sync_logs_collection_response()
    }
  end

  @doc """
  Example SCIM clients list response data.
  """
  def scim_clients_list_example do
    %{
      data: [
        %{
          id: "401",
          type: "scim_client",
          attributes: %{
            name: "Example SCIM Client",
            description: "SCIM integration for Example Service",
            base_url: "https://api.example.com/scim/v2",
            auth_type: "bearer",
            auth_username: nil,
            attribute_mapping: nil,
            is_active: true,
            sync_users: true,
            sync_groups: true,
            organization_id: 123,
            inserted_at: "2024-01-15T10:00:00Z",
            updated_at: "2024-01-15T10:00:00Z"
          },
          links: %{
            self: "/acme-corp/api/scim-clients/401"
          }
        },
        %{
          id: "402",
          type: "scim_client",
          attributes: %{
            name: "GitHub SCIM",
            description: "GitHub Enterprise provisioning",
            base_url: "https://api.github.com/scim/v2/organizations/acme",
            auth_type: "bearer",
            auth_username: nil,
            attribute_mapping: nil,
            is_active: true,
            sync_users: true,
            sync_groups: false,
            organization_id: 123,
            inserted_at: "2024-02-01T14:30:00Z",
            updated_at: "2024-02-01T14:30:00Z"
          },
          links: %{
            self: "/acme-corp/api/scim-clients/402"
          }
        }
      ],
      links: %{
        self: "/acme-corp/api/scim-clients?page=1&per_page=25",
        first: "/acme-corp/api/scim-clients?page=1&per_page=25"
      },
      meta: %{
        total: 2,
        page: 1,
        per_page: 25
      }
    }
  end

  @doc """
  Example SCIM client response data.
  """
  def scim_client_example do
    %{
      data: %{
        id: "401",
        type: "scim_client",
        attributes: %{
          name: "Example SCIM Client",
          description: "SCIM integration for Example Service",
          base_url: "https://api.example.com/scim/v2",
          auth_type: "bearer",
          auth_username: nil,
          attribute_mapping: nil,
          is_active: true,
          sync_users: true,
          sync_groups: true,
          organization_id: 123,
          inserted_at: "2024-01-15T10:00:00Z",
          updated_at: "2024-01-15T10:00:00Z"
        },
        links: %{
          self: "/acme-corp/api/scim-clients/401"
        }
      },
      links: %{
        self: "/acme-corp/api/scim-clients/401"
      }
    }
  end

  @doc """
  Example SCIM sync logs list response data.
  """
  def scim_sync_logs_example do
    %{
      data: [
        %{
          id: "1001",
          type: "scim_sync_log",
          attributes: %{
            scim_client_id: 401,
            resource_type: "User",
            resource_id: 789,
            operation: "created",
            status: "success",
            http_status: 201,
            request_body: "{\"userName\":\"john.doe@example.com\"}",
            response_body: "{\"id\":\"scim-user-123\"}",
            error_message: nil,
            retry_count: 0,
            next_retry_at: nil,
            inserted_at: "2024-03-01T10:15:00Z",
            updated_at: "2024-03-01T10:15:01Z"
          },
          links: %{
            self: "/acme-corp/api/scim-clients/401/logs/1001"
          }
        },
        %{
          id: "1002",
          type: "scim_sync_log",
          attributes: %{
            scim_client_id: 401,
            resource_type: "User",
            resource_id: 790,
            operation: "updated",
            status: "failed",
            http_status: 500,
            request_body: "{\"userName\":\"jane.smith@example.com\"}",
            response_body: "{\"error\":\"Internal server error\"}",
            error_message: "HTTP 500: Internal server error",
            retry_count: 1,
            next_retry_at: "2024-03-01T10:20:00Z",
            inserted_at: "2024-03-01T10:12:00Z",
            updated_at: "2024-03-01T10:12:05Z"
          },
          links: %{
            self: "/acme-corp/api/scim-clients/401/logs/1002"
          }
        }
      ],
      links: %{
        self: "/acme-corp/api/scim-clients/401/logs?page=1&per_page=50",
        first: "/acme-corp/api/scim-clients/401/logs?page=1&per_page=50"
      },
      meta: %{
        total: 2,
        page: 1,
        per_page: 50
      }
    }
  end

  defp scim_client_attributes do
    %{
      type: "object",
      properties: %{
        name: %{type: "string", description: "SCIM client name"},
        description: %{type: "string", description: "Optional description"},
        base_url: %{
          type: "string",
          format: "uri",
          description: "SCIM 2.0 endpoint base URL"
        },
        auth_type: %{
          type: "string",
          enum: ["bearer", "basic"],
          description: "Authentication method (bearer token or basic auth)"
        },
        auth_username: %{
          type: "string",
          nullable: true,
          description: "Username for basic auth (null for bearer)"
        },
        attribute_mapping: %{
          type: "string",
          nullable: true,
          description: "JSON configuration for custom attribute mapping"
        },
        is_active: %{
          type: "boolean",
          description: "Whether the SCIM client is active for provisioning"
        },
        sync_users: %{
          type: "boolean",
          description: "Whether to synchronize user changes"
        },
        sync_groups: %{
          type: "boolean",
          description: "Whether to synchronize group changes"
        },
        organization_id: %{type: "integer", description: "Organization ID"},
        inserted_at: %{type: "string", format: "date-time", description: "Creation timestamp"},
        updated_at: %{type: "string", format: "date-time", description: "Last update timestamp"}
      }
    }
  end

  defp scim_client_resource do
    %{
      type: "object",
      properties: %{
        id: %{type: "string", description: "SCIM client ID"},
        type: %{type: "string", enum: ["scim_client"], description: "Resource type"},
        attributes: %{"$ref" => "#/components/schemas/ScimClientAttributes"},
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["id", "type", "attributes", "links"]
    }
  end

  defp scim_client_response do
    %{
      type: "object",
      properties: %{
        data: %{"$ref" => "#/components/schemas/ScimClientResource"},
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["data", "links"]
    }
  end

  defp scim_clients_collection_response do
    %{
      type: "object",
      properties: %{
        data: %{type: "array", items: %{"$ref" => "#/components/schemas/ScimClientResource"}},
        links: %{"$ref" => "#/components/schemas/CollectionLinks"},
        meta: %{"$ref" => "#/components/schemas/PaginationMeta"}
      },
      required: ["data", "links", "meta"]
    }
  end

  defp scim_client_create_request do
    %{
      type: "object",
      properties: %{
        scim_client: %{
          type: "object",
          properties: %{
            name: %{type: "string", description: "SCIM client name"},
            description: %{type: "string", description: "Optional description"},
            base_url: %{
              type: "string",
              format: "uri",
              description: "SCIM 2.0 endpoint base URL (e.g., https://api.slack.com/scim/v2)"
            },
            auth_type: %{
              type: "string",
              enum: ["bearer", "basic"],
              default: "bearer",
              description: "Authentication method"
            },
            auth_credential: %{
              type: "string",
              description: "Bearer token or password for authentication"
            },
            auth_username: %{
              type: "string",
              description: "Username (required for basic auth, omit for bearer)"
            },
            attribute_mapping: %{
              type: "string",
              description: "Optional JSON configuration for custom attribute mapping"
            },
            is_active: %{
              type: "boolean",
              default: false,
              description: "Whether to activate immediately"
            },
            sync_users: %{
              type: "boolean",
              default: true,
              description: "Whether to synchronize user changes"
            },
            sync_groups: %{
              type: "boolean",
              default: true,
              description: "Whether to synchronize group changes"
            }
          },
          required: ["name", "base_url", "auth_type", "auth_credential"]
        }
      },
      required: ["scim_client"]
    }
  end

  defp scim_client_update_request do
    %{
      type: "object",
      properties: %{
        scim_client: %{
          type: "object",
          properties: %{
            name: %{type: "string", description: "SCIM client name"},
            description: %{type: "string", description: "Optional description"},
            base_url: %{
              type: "string",
              format: "uri",
              description: "SCIM 2.0 endpoint base URL"
            },
            auth_type: %{
              type: "string",
              enum: ["bearer", "basic"],
              description: "Authentication method"
            },
            auth_credential: %{
              type: "string",
              description: "Bearer token or password (leave blank to keep current value)"
            },
            auth_username: %{
              type: "string",
              description: "Username for basic auth"
            },
            attribute_mapping: %{
              type: "string",
              description: "JSON configuration for custom attribute mapping"
            },
            is_active: %{
              type: "boolean",
              description: "Whether the SCIM client is active"
            },
            sync_users: %{
              type: "boolean",
              description: "Whether to synchronize user changes"
            },
            sync_groups: %{
              type: "boolean",
              description: "Whether to synchronize group changes"
            }
          }
        }
      },
      required: ["scim_client"]
    }
  end

  defp scim_sync_log_attributes do
    %{
      type: "object",
      properties: %{
        scim_client_id: %{type: "integer", description: "SCIM client ID"},
        resource_type: %{
          type: "string",
          enum: ["User", "Group"],
          description: "Type of resource synchronized"
        },
        resource_id: %{type: "integer", description: "Internal resource ID"},
        operation: %{
          type: "string",
          enum: ["created", "updated", "deleted"],
          description: "SCIM operation performed"
        },
        status: %{
          type: "string",
          enum: ["pending", "success", "failed"],
          description: "Synchronization status"
        },
        http_status: %{
          type: "integer",
          nullable: true,
          description: "HTTP response status code"
        },
        request_body: %{
          type: "string",
          nullable: true,
          description: "JSON request body sent to SCIM endpoint"
        },
        response_body: %{
          type: "string",
          nullable: true,
          description: "JSON response received from SCIM endpoint"
        },
        error_message: %{
          type: "string",
          nullable: true,
          description: "Error message if synchronization failed"
        },
        retry_count: %{
          type: "integer",
          description: "Number of retry attempts"
        },
        next_retry_at: %{
          type: "string",
          format: "date-time",
          nullable: true,
          description: "Scheduled time for next retry attempt"
        },
        inserted_at: %{type: "string", format: "date-time", description: "Creation timestamp"},
        updated_at: %{type: "string", format: "date-time", description: "Last update timestamp"}
      }
    }
  end

  defp scim_sync_log_resource do
    %{
      type: "object",
      properties: %{
        id: %{type: "string", description: "Sync log ID"},
        type: %{type: "string", enum: ["scim_sync_log"], description: "Resource type"},
        attributes: %{"$ref" => "#/components/schemas/ScimSyncLogAttributes"},
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["id", "type", "attributes", "links"]
    }
  end

  defp scim_sync_logs_collection_response do
    %{
      type: "object",
      properties: %{
        data: %{type: "array", items: %{"$ref" => "#/components/schemas/ScimSyncLogResource"}},
        links: %{"$ref" => "#/components/schemas/CollectionLinks"},
        meta: %{"$ref" => "#/components/schemas/PaginationMeta"}
      },
      required: ["data", "links", "meta"]
    }
  end
end
