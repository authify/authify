defmodule AuthifyWeb.API.OpenAPI.Schemas.Tasks do
  @moduledoc """
  OpenAPI schema definitions for Tasks and Task Logs.
  """

  def build do
    %{
      "TaskAttributes" => task_attributes(),
      "TaskResource" => task_resource(),
      "TaskResponse" => task_response(),
      "TasksCollectionResponse" => tasks_collection_response(),
      "TaskLogAttributes" => task_log_attributes(),
      "TaskLogResource" => task_log_resource(),
      "TaskLogsCollectionResponse" => task_logs_collection_response()
    }
  end

  defp task_attributes do
    %{
      type: "object",
      properties: %{
        type: %{type: "string", description: "Task type (e.g., 'email', 'scim')"},
        action: %{
          type: "string",
          description: "Task action (e.g., 'send_invitation', 'sync_user')"
        },
        status: %{
          type: "string",
          description: "Current task status",
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
        },
        params: %{type: "object", description: "Task parameters"},
        priority: %{
          type: "integer",
          description: "Task priority (0 = default, higher = more important)"
        },
        max_retries: %{type: "integer", description: "Maximum retry attempts"},
        retry_count: %{type: "integer", description: "Current retry count"},
        timeout_seconds: %{
          type: "integer",
          nullable: true,
          description: "Task execution timeout in seconds"
        },
        results: %{type: "object", description: "Task execution results"},
        errors: %{type: "object", description: "Task error details"},
        correlation_id: %{
          type: "string",
          nullable: true,
          description: "Correlation ID for tracing related tasks"
        },
        metadata: %{type: "object", description: "Additional task metadata"},
        organization_id: %{type: "integer", description: "Organization ID"},
        parent_id: %{
          type: "string",
          format: "uuid",
          nullable: true,
          description: "Parent task ID for workflow child tasks"
        },
        scheduled_at: %{
          type: "string",
          format: "date-time",
          nullable: true,
          description: "Scheduled execution time"
        },
        started_at: %{
          type: "string",
          format: "date-time",
          nullable: true,
          description: "Actual start time"
        },
        completed_at: %{
          type: "string",
          format: "date-time",
          nullable: true,
          description: "Completion time"
        },
        failed_at: %{
          type: "string",
          format: "date-time",
          nullable: true,
          description: "Failure time"
        },
        expires_at: %{
          type: "string",
          format: "date-time",
          nullable: true,
          description: "Expiration time for wait tasks"
        },
        inserted_at: %{type: "string", format: "date-time", description: "Creation timestamp"},
        updated_at: %{type: "string", format: "date-time", description: "Last update timestamp"}
      }
    }
  end

  defp task_resource do
    %{
      type: "object",
      properties: %{
        id: %{type: "string", format: "uuid", description: "Task ID (UUID v7)"},
        type: %{type: "string", enum: ["task"], description: "Resource type"},
        attributes: %{"$ref" => "#/components/schemas/TaskAttributes"},
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["id", "type", "attributes", "links"]
    }
  end

  defp task_response do
    %{
      type: "object",
      properties: %{
        data: %{"$ref" => "#/components/schemas/TaskResource"},
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["data", "links"]
    }
  end

  defp tasks_collection_response do
    %{
      type: "object",
      properties: %{
        data: %{type: "array", items: %{"$ref" => "#/components/schemas/TaskResource"}},
        links: %{"$ref" => "#/components/schemas/CollectionLinks"},
        meta: %{"$ref" => "#/components/schemas/PaginationMeta"}
      },
      required: ["data", "links", "meta"]
    }
  end

  defp task_log_attributes do
    %{
      type: "object",
      properties: %{
        message: %{type: "string", description: "Log message"},
        level: %{
          type: "string",
          enum: ["debug", "info", "warning", "error"],
          description: "Log severity level"
        },
        task_id: %{type: "string", format: "uuid", description: "Associated task ID"},
        inserted_at: %{type: "string", format: "date-time", description: "Log entry timestamp"}
      }
    }
  end

  defp task_log_resource do
    %{
      type: "object",
      properties: %{
        id: %{type: "string", description: "Task log entry ID"},
        type: %{type: "string", enum: ["task_log"], description: "Resource type"},
        attributes: %{"$ref" => "#/components/schemas/TaskLogAttributes"},
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["id", "type", "attributes", "links"]
    }
  end

  defp task_logs_collection_response do
    %{
      type: "object",
      properties: %{
        data: %{type: "array", items: %{"$ref" => "#/components/schemas/TaskLogResource"}},
        links: %{"$ref" => "#/components/schemas/CollectionLinks"},
        meta: %{"$ref" => "#/components/schemas/PaginationMeta"}
      },
      required: ["data", "links", "meta"]
    }
  end
end
