defmodule AuthifyWeb.API.OpenAPI.Paths.Tasks do
  @moduledoc """
  OpenAPI path definitions for Task Management endpoints.
  """

  def build do
    %{
      "/{org_slug}/api/tasks" => build_tasks_path(),
      "/{org_slug}/api/tasks/{id}" => build_task_path(),
      "/{org_slug}/api/tasks/{id}/logs" => build_task_logs_path(),
      "/{org_slug}/api/tasks/{id}/cancel" => build_task_cancel_path()
    }
  end

  defp build_tasks_path do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Tasks"],
        summary: "List tasks",
        description:
          "Get a paginated list of tasks for the organization with optional filtering by status, type, and action. Requires `tasks:read` scope.",
        operationId: "listTasks",
        security: [
          %{"OAuth2" => ["tasks:read"]},
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
            name: "status",
            in: "query",
            required: false,
            description:
              "Filter by task status (e.g., 'pending', 'running', 'completed', 'failed', 'cancelled')",
            schema: %{
              type: "string",
              enum: [
                "pending",
                "scheduled",
                "running",
                "waiting",
                "retrying",
                "completing",
                "failing",
                "expiring",
                "cancelling",
                "timing_out",
                "skipping",
                "completed",
                "failed",
                "expired",
                "timed_out",
                "cancelled",
                "skipped"
              ]
            }
          },
          %{
            name: "type",
            in: "query",
            required: false,
            description: "Filter by task type (e.g., 'email', 'scim')",
            schema: %{type: "string"}
          },
          %{
            name: "action",
            in: "query",
            required: false,
            description: "Filter by task action (e.g., 'send_invitation', 'sync_user')",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Tasks retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/TasksCollectionResponse"}
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"}
        }
      }
    }
  end

  defp build_task_path do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Tasks"],
        summary: "Get task details",
        description:
          "Get a specific task by ID, including its metadata and results. Requires `tasks:read` scope.",
        operationId: "getTask",
        security: [
          %{"OAuth2" => ["tasks:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Task ID (UUID v7)",
            schema: %{type: "string", format: "uuid"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Task retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/TaskResponse"}
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

  defp build_task_logs_path do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Tasks"],
        summary: "Get task logs",
        description:
          "Get execution logs for a specific task, including status transitions and messages. Requires `tasks:read` scope.",
        operationId: "getTaskLogs",
        security: [
          %{"OAuth2" => ["tasks:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Task ID (UUID v7)",
            schema: %{type: "string", format: "uuid"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Task logs retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/TaskLogsCollectionResponse"}
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

  defp build_task_cancel_path do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      post: %{
        tags: ["Tasks"],
        summary: "Cancel a task",
        description:
          "Cancel a task that is in an active state (pending, scheduled, running, waiting, retrying). " <>
            "Cascades cancellation to child tasks in workflows. Requires `tasks:write` scope.",
        operationId: "cancelTask",
        security: [
          %{"OAuth2" => ["tasks:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Task ID (UUID v7)",
            schema: %{type: "string", format: "uuid"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Task cancelled successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/TaskResponse"}
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"},
          "422" => %{
            description: "Invalid state transition (task is already in a terminal state)",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{
                  type: "object",
                  properties: %{
                    error: %{
                      type: "object",
                      properties: %{
                        type: %{type: "string", example: "invalid_state_transition"},
                        message: %{
                          type: "string",
                          example: "Cannot cancel task in completed state"
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  end
end
