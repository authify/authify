defmodule AuthifyWeb.AuditLogsHTML do
  @moduledoc """
  HTML views for audit log display.
  """

  use AuthifyWeb, :html

  embed_templates "audit_logs_html/*"

  @doc """
  Formats an event type for display.
  """
  def format_event_type(event_type) do
    event_type
    |> String.replace("_", " ")
    |> String.split()
    |> Enum.map_join(" ", &String.capitalize/1)
  end

  @doc """
  Returns a CSS class for event outcome badges.
  """
  def outcome_badge_class("success"), do: "badge bg-success"
  def outcome_badge_class("failure"), do: "badge bg-danger"
  def outcome_badge_class("denied"), do: "badge bg-warning"
  def outcome_badge_class(_), do: "badge bg-secondary"

  @doc """
  Returns a CSS class for event type badges.
  """
  def event_type_badge_class(event_type) do
    cond do
      String.contains?(event_type, "login") -> "badge bg-primary"
      String.contains?(event_type, "logout") -> "badge bg-info"
      String.contains?(event_type, "oauth") -> "badge bg-purple"
      String.contains?(event_type, "saml") -> "badge bg-indigo"
      String.contains?(event_type, "user") -> "badge bg-warning"
      String.contains?(event_type, "role") -> "badge bg-danger"
      true -> "badge bg-secondary"
    end
  end

  @doc """
  Formats metadata as JSON for display.
  """
  def format_metadata(nil), do: "{}"

  def format_metadata(metadata) when is_map(metadata) do
    Jason.encode!(metadata, pretty: true)
  end

  @doc """
  Formats a datetime for display.
  """
  def format_datetime(datetime) do
    Calendar.strftime(datetime, "%Y-%m-%d %H:%M:%S UTC")
  end
end
