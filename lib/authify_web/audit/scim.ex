defmodule AuthifyWeb.Audit.SCIM do
  @moduledoc """
  Audit logging for SCIM client lifecycle events.
  """

  alias AuthifyWeb.Audit.Base

  @doc """
  Logs a generic SCIM client lifecycle event.
  """
  def log_scim_client_event(conn, event_type, scim_client, metadata, opts \\ []) do
    Base.log_event_async(
      conn,
      event_type,
      opts[:resource_type] || "scim_client",
      scim_client.id,
      opts[:outcome] || "success",
      Map.merge(metadata, %{
        "client_name" => scim_client.name,
        "client_id" => scim_client.id
      })
    )
  end
end
