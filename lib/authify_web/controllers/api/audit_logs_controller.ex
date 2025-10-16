defmodule AuthifyWeb.API.AuditLogsController do
  use AuthifyWeb.API.BaseController

  alias Authify.AuditLog

  @doc """
  GET /{org_slug}/api/audit-logs

  List audit logs for the current organization with pagination and filtering.
  Requires audit_logs:read scope.

  Query Parameters:
  - page: Page number (default: 1)
  - per_page: Results per page (default: 25, max: 100)
  - event_type: Filter by event type (e.g., "user_created", "login_success")
  - actor_id: Filter by actor ID
  - actor_type: Filter by actor type (user, api_client, application, system)
  - resource_type: Filter by resource type (e.g., "user", "oauth_application")
  - resource_id: Filter by resource ID
  - outcome: Filter by outcome (success, failure, denied)
  - from_date: Filter events after this date (ISO 8601 format)
  - to_date: Filter events before this date (ISO 8601 format)
  """
  def index(conn, params) do
    case ensure_scope(conn, "audit_logs:read") do
      :ok ->
        organization = conn.assigns.current_organization
        page = String.to_integer(params["page"] || "1")
        per_page = min(String.to_integer(params["per_page"] || "25"), 100)

        # Build filter options
        filter_opts =
          build_filter_options(params)
          |> Keyword.put(:organization_id, organization.id)
          |> Keyword.put(:page, page)
          |> Keyword.put(:per_page, per_page)

        # Get audit logs with filters
        audit_logs = AuditLog.list_events(filter_opts)

        total =
          AuditLog.count_events(Keyword.delete(filter_opts, :page) |> Keyword.delete(:per_page))

        page_info = %{
          page: page,
          per_page: per_page,
          total: total
        }

        render_collection_response(conn, audit_logs,
          resource_type: "audit_log",
          page_info: page_info
        )

      {:error, response} ->
        response
    end
  end

  @doc """
  GET /{org_slug}/api/audit-logs/:id

  Get a specific audit log entry by ID.
  Requires audit_logs:read scope.
  """
  def show(conn, %{"id" => id}) do
    case ensure_scope(conn, "audit_logs:read") do
      :ok ->
        organization = conn.assigns.current_organization

        case AuditLog.get_event(id, organization_id: organization.id) do
          {:ok, event} ->
            render_api_response(conn, event, resource_type: "audit_log")

          {:error, :not_found} ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "Audit log entry not found in organization"
            )
        end

      {:error, response} ->
        response
    end
  end

  # Private helper to build filter options from query params
  defp build_filter_options(params) do
    []
    |> maybe_add_filter(:event_type, params["event_type"])
    |> maybe_add_filter(:actor_id, params["actor_id"])
    |> maybe_add_filter(:actor_type, params["actor_type"])
    |> maybe_add_filter(:resource_type, params["resource_type"])
    |> maybe_add_filter(:resource_id, params["resource_id"])
    |> maybe_add_filter(:outcome, params["outcome"])
    |> maybe_add_date_filter(:from_date, params["from_date"])
    |> maybe_add_date_filter(:to_date, params["to_date"])
  end

  defp maybe_add_filter(opts, _key, nil), do: opts
  defp maybe_add_filter(opts, _key, ""), do: opts
  defp maybe_add_filter(opts, key, value), do: Keyword.put(opts, key, value)

  defp maybe_add_date_filter(opts, _key, nil), do: opts
  defp maybe_add_date_filter(opts, _key, ""), do: opts

  defp maybe_add_date_filter(opts, key, date_string) do
    case DateTime.from_iso8601(date_string) do
      {:ok, datetime, _offset} -> Keyword.put(opts, key, datetime)
      {:error, _} -> opts
    end
  end
end
