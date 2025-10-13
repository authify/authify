defmodule AuthifyWeb.Helpers.AuditHelper do
  @moduledoc """
  Helper functions for audit logging in controllers.

  Supports both user actors (web UI, personal access tokens) and
  application actors (OAuth client credentials flow).
  """

  alias Authify.AuditLog

  @doc """
  Logs an audit event from a controller connection.

  Automatically extracts actor information from conn.assigns and determines
  whether the actor is a user or an application (service account).

  ## Parameters
  - `conn` - The Plug.Conn with authentication assigns
  - `event_type` - Atom representing the event type (e.g., :oauth_client_created)
  - `resource_type` - String representing the resource type (e.g., "oauth_application")
  - `resource_id` - Integer ID of the affected resource
  - `outcome` - String outcome ("success", "failure", "denied")
  - `metadata` - Map of additional event metadata (optional)

  ## Examples

      # Log a successful resource creation
      log_event_async(conn, :oauth_client_created, "oauth_application", app.id, "success", %{
        application_type: app.application_type
      })

      # Log a failed action
      log_event_async(conn, :permission_denied, "organization", org_id, "denied", %{
        reason: "insufficient_permissions"
      })
  """
  def log_event_async(conn, event_type, resource_type, resource_id, outcome, metadata \\ %{}) do
    organization = conn.assigns.current_organization
    actor_type = conn.assigns[:actor_type] || :user

    base_attrs = %{
      organization_id: organization.id,
      resource_type: resource_type,
      resource_id: resource_id,
      outcome: outcome,
      ip_address: get_ip_address(conn),
      user_agent: get_user_agent(conn),
      metadata: metadata
    }

    attrs =
      case actor_type do
        :user ->
          user = conn.assigns.current_user

          Map.merge(base_attrs, %{
            actor_type: "user",
            actor_id: user.id,
            actor_name: build_user_name(user)
          })

        :application ->
          application = conn.assigns.current_application

          Map.merge(base_attrs, %{
            actor_type: "application",
            actor_id: application.id,
            actor_name: application.name
          })
      end

    AuditLog.log_event_async(event_type, attrs)
  end

  @doc """
  Extracts IP address from connection.
  """
  def get_ip_address(conn) do
    case Plug.Conn.get_req_header(conn, "x-forwarded-for") do
      [ip | _] -> ip
      [] -> to_string(:inet_parse.ntoa(conn.remote_ip))
    end
  end

  @doc """
  Extracts user agent from connection.
  """
  def get_user_agent(conn) do
    case Plug.Conn.get_req_header(conn, "user-agent") do
      [user_agent | _] -> user_agent
      [] -> "Unknown"
    end
  end

  defp build_user_name(user) do
    "#{user.first_name} #{user.last_name}"
  end
end
