defmodule AuthifyWeb.MaintenanceHTML do
  use AuthifyWeb, :html

  embed_templates "maintenance_html/*"

  def format_uptime(uptime_seconds) when is_integer(uptime_seconds) do
    hours = div(uptime_seconds, 3600)
    minutes = div(rem(uptime_seconds, 3600), 60)
    seconds = rem(uptime_seconds, 60)

    "#{hours}h #{minutes}m #{seconds}s"
  end

  def format_memory_percentage(used, total)
      when is_number(used) and is_number(total) and total > 0 do
    percentage = (used / total * 100) |> Float.round(1)
    "#{percentage}%"
  end

  def format_memory_percentage(_, _), do: "N/A"

  def status_badge_class("completed"), do: "bg-success"
  def status_badge_class("running"), do: "bg-primary"
  def status_badge_class("failed"), do: "bg-danger"
  def status_badge_class(_), do: "bg-secondary"
end
