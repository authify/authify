defmodule AuthifyWeb.API.TasksController do
  use AuthifyWeb.API.BaseController

  alias Authify.Security.Sanitizer
  alias Authify.Tasks
  alias Authify.Tasks.Task

  @doc """
  GET /{org_slug}/api/tasks

  List tasks for the current organization with pagination and optional filters.
  Supports filtering by status, type, and action query parameters.
  Requires tasks:read scope.
  """
  def index(conn, params) do
    case ensure_scope(conn, "tasks:read") do
      :ok ->
        organization = conn.assigns.current_organization
        page = String.to_integer(params["page"] || "1")
        per_page = min(String.to_integer(params["per_page"] || "25"), 100)

        opts =
          [page: page, per_page: per_page]
          |> maybe_add_filter(:status, params["status"])
          |> maybe_add_filter(:type, params["type"])
          |> maybe_add_filter(:action, params["action"])

        {tasks, total} = Tasks.list_tasks(organization.id, opts)
        sanitized_tasks = Enum.map(tasks, &sanitize_task/1)

        render_collection_response(conn, sanitized_tasks,
          resource_type: "task",
          exclude: [:__meta__],
          page_info: %{page: page, per_page: per_page, total: total}
        )

      {:error, response} ->
        response
    end
  end

  @doc """
  GET /{org_slug}/api/tasks/:id

  Get a specific task by ID, including its metadata and results.
  Requires tasks:read scope.
  """
  def show(conn, %{"id" => id}) do
    case ensure_scope(conn, "tasks:read") do
      :ok ->
        organization = conn.assigns.current_organization

        case get_task_in_org(id, organization.id) do
          nil ->
            render_error_response(conn, :not_found, "resource_not_found", "Task not found")

          task ->
            sanitized_task = sanitize_task(task)
            render_api_response(conn, sanitized_task, resource_type: "task", exclude: [:__meta__])
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  GET /{org_slug}/api/tasks/:id/logs

  Get execution logs for a specific task.
  Requires tasks:read scope.
  """
  def logs(conn, %{"id" => id}) do
    case ensure_scope(conn, "tasks:read") do
      :ok ->
        organization = conn.assigns.current_organization

        case get_task_in_org(id, organization.id) do
          nil ->
            render_error_response(conn, :not_found, "resource_not_found", "Task not found")

          task ->
            logs = Tasks.list_task_logs(task)
            sanitized_logs = Enum.map(logs, &sanitize_log/1)

            total = length(logs)

            render_collection_response(conn, sanitized_logs,
              resource_type: "task_log",
              exclude: [:__meta__],
              page_info: %{page: 1, per_page: max(total, 25), total: total}
            )
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  POST /{org_slug}/api/tasks/:id/cancel

  Cancel a task. Works for tasks in active states (pending, scheduled,
  running, waiting, retrying). Cascades cancellation to child tasks.
  Requires tasks:write scope.
  """
  def cancel(conn, %{"id" => id}) do
    case ensure_scope(conn, "tasks:write") do
      :ok ->
        organization = conn.assigns.current_organization

        case get_task_in_org(id, organization.id) do
          nil ->
            render_error_response(conn, :not_found, "resource_not_found", "Task not found")

          task ->
            case Tasks.cancel_task(task) do
              {:ok, cancelled_task} ->
                sanitized_task = sanitize_task(cancelled_task)

                render_api_response(conn, sanitized_task,
                  resource_type: "task",
                  exclude: [:__meta__]
                )

              {:error, {:invalid_transition, from_state, _to_state}} ->
                render_error_response(
                  conn,
                  :unprocessable_entity,
                  "invalid_state_transition",
                  "Cannot cancel task in #{from_state} state"
                )

              {:error, _reason} ->
                render_error_response(
                  conn,
                  :unprocessable_entity,
                  "cancellation_failed",
                  "Failed to cancel task"
                )
            end
        end

      {:error, response} ->
        response
    end
  end

  # --- Private Helpers ---

  defp get_task_in_org(id, organization_id) do
    case Tasks.get_task(id) do
      %Task{organization_id: ^organization_id} = task -> task
      _ -> nil
    end
  end

  defp maybe_add_filter(opts, :status, status) when is_binary(status) do
    case parse_status(status) do
      {:ok, atom_status} -> Keyword.put(opts, :status, atom_status)
      :error -> opts
    end
  end

  defp maybe_add_filter(opts, key, value) when is_binary(value) do
    Keyword.put(opts, key, value)
  end

  defp maybe_add_filter(opts, _key, _value), do: opts

  defp parse_status(status) do
    atom_status = String.to_existing_atom(status)

    if atom_status in Task.all_states() do
      {:ok, atom_status}
    else
      :error
    end
  rescue
    ArgumentError -> :error
  end

  # Sanitizes sensitive data from task errors before returning via API
  defp sanitize_task(%Task{errors: errors} = task) when is_map(errors) and errors != %{} do
    %{task | errors: Sanitizer.sanitize_map(errors)}
  end

  defp sanitize_task(%Task{} = task), do: task

  # Sanitizes sensitive data from task log entries before returning via API
  defp sanitize_log(%{log_data: log_data} = log) when is_binary(log_data) do
    %{log | log_data: Sanitizer.sanitize(log_data)}
  end

  defp sanitize_log(log), do: log
end
