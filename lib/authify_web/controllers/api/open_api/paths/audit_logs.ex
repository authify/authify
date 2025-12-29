defmodule AuthifyWeb.API.OpenAPI.Paths.AuditLogs do
  @moduledoc """
  OpenAPI path definitions for Audit Logs endpoints.
  """

  def build do
    %{
      "/organizations/{org_slug}/audit_logs" => build_audit_logs_path(),
      "/organizations/{org_slug}/audit_logs/{id}" => build_audit_log_path()
    }
  end

  defp build_audit_logs_path do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Audit Logs"],
        summary: "List audit logs",
        description:
          "Get a paginated list of audit log entries for the organization with optional filtering. Requires `audit_logs:read` scope.",
        security: [
          %{"OAuth2" => ["audit_logs:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "page",
            in: "query",
            required: false,
            description: "Page number (default: 1)",
            schema: %{type: "integer", minimum: 1, default: 1}
          },
          %{
            name: "per_page",
            in: "query",
            required: false,
            description: "Results per page (default: 25, max: 100)",
            schema: %{type: "integer", minimum: 1, maximum: 100, default: 25}
          },
          %{
            name: "event_type",
            in: "query",
            required: false,
            description:
              "Filter by event type (e.g., 'user_created', 'login_success', 'oauth_client_created')",
            schema: %{type: "string"}
          },
          %{
            name: "actor_id",
            in: "query",
            required: false,
            description: "Filter by actor ID",
            schema: %{type: "string"}
          },
          %{
            name: "actor_type",
            in: "query",
            required: false,
            description: "Filter by actor type",
            schema: %{type: "string", enum: ["user", "api_client", "application", "system"]}
          },
          %{
            name: "resource_type",
            in: "query",
            required: false,
            description:
              "Filter by resource type (e.g., 'user', 'oauth_application', 'invitation')",
            schema: %{type: "string"}
          },
          %{
            name: "resource_id",
            in: "query",
            required: false,
            description: "Filter by resource ID",
            schema: %{type: "string"}
          },
          %{
            name: "outcome",
            in: "query",
            required: false,
            description: "Filter by outcome",
            schema: %{type: "string", enum: ["success", "failure", "denied"]}
          },
          %{
            name: "from_date",
            in: "query",
            required: false,
            description: "Filter events after this date (ISO 8601 format)",
            schema: %{type: "string", format: "date-time"}
          },
          %{
            name: "to_date",
            in: "query",
            required: false,
            description: "Filter events before this date (ISO 8601 format)",
            schema: %{type: "string", format: "date-time"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Audit logs retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{
                  type: "object",
                  properties: %{
                    data: %{
                      type: "array",
                      items: %{
                        type: "object",
                        properties: %{
                          id: %{type: "string"},
                          type: %{type: "string", example: "audit_log"},
                          attributes: %{
                            type: "object",
                            properties: %{
                              event_type: %{type: "string"},
                              actor_type: %{type: "string"},
                              actor_id: %{type: "string"},
                              actor_name: %{type: "string"},
                              resource_type: %{type: "string"},
                              resource_id: %{type: "string"},
                              outcome: %{type: "string"},
                              ip_address: %{type: "string"},
                              user_agent: %{type: "string"},
                              metadata: %{type: "object"},
                              inserted_at: %{type: "string", format: "date-time"}
                            }
                          }
                        }
                      }
                    },
                    meta: %{
                      type: "object",
                      properties: %{
                        page: %{type: "integer"},
                        per_page: %{type: "integer"},
                        total: %{type: "integer"}
                      }
                    }
                  }
                }
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"}
        }
      }
    }
  end

  defp build_audit_log_path do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Audit Logs"],
        summary: "Get audit log entry",
        description: "Get a specific audit log entry by ID. Requires `audit_logs:read` scope.",
        security: [
          %{"OAuth2" => ["audit_logs:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Audit log entry ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Audit log entry retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{
                  type: "object",
                  properties: %{
                    data: %{
                      type: "object",
                      properties: %{
                        id: %{type: "string"},
                        type: %{type: "string", example: "audit_log"},
                        attributes: %{
                          type: "object",
                          properties: %{
                            event_type: %{type: "string"},
                            actor_type: %{type: "string"},
                            actor_id: %{type: "string"},
                            actor_name: %{type: "string"},
                            resource_type: %{type: "string"},
                            resource_id: %{type: "string"},
                            outcome: %{type: "string"},
                            ip_address: %{type: "string"},
                            user_agent: %{type: "string"},
                            metadata: %{type: "object"},
                            inserted_at: %{type: "string", format: "date-time"}
                          }
                        }
                      }
                    }
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
end
