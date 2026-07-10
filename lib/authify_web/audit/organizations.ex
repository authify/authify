defmodule AuthifyWeb.Audit.Organizations do
  @moduledoc """
  Audit logging for organization lifecycle events.
  """

  alias AuthifyWeb.Audit.Base

  @doc """
  Logs a generic organization lifecycle event.
  """
  def log_organization_event(conn, event_type, target_organization, metadata, opts \\ []) do
    Base.log_event_async(
      conn,
      event_type,
      opts[:resource_type] || "organization",
      target_organization.id,
      opts[:outcome] || "success",
      Map.merge(metadata, %{
        organization_name: target_organization.name,
        organization_id: target_organization.id
      })
    )
  end
end
