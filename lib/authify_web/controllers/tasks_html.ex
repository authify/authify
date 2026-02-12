defmodule AuthifyWeb.TasksHTML do
  @moduledoc """
  HTML views for task list display (index only; detail view uses LiveView).
  """

  use AuthifyWeb, :html

  embed_templates "tasks_html/*"

  @doc """
  Returns a CSS class for task status badges based on state category.
  """
  def status_badge_class(status)
      when status in [:scheduled, :pending, :running, :waiting, :retrying] do
    "badge bg-primary"
  end

  def status_badge_class(status)
      when status in [:completing, :failing, :expiring, :cancelling, :timing_out, :skipping] do
    "badge bg-warning"
  end

  def status_badge_class(:completed), do: "badge bg-success"
  def status_badge_class(:failed), do: "badge bg-danger"
  def status_badge_class(:expired), do: "badge bg-secondary"
  def status_badge_class(:timed_out), do: "badge bg-danger"
  def status_badge_class(:cancelled), do: "badge bg-secondary"
  def status_badge_class(:skipped), do: "badge bg-info"
  def status_badge_class(_), do: "badge bg-secondary"

  @doc """
  Formats a status atom for display.
  """
  def format_status(status) do
    status
    |> to_string()
    |> String.replace("_", " ")
    |> String.capitalize()
  end

  @doc """
  Formats a datetime for display.
  """
  def format_datetime(nil), do: "—"

  def format_datetime(datetime) do
    Calendar.strftime(datetime, "%Y-%m-%d %H:%M:%S UTC")
  end

  @doc """
  Truncates a UUID for display.
  """
  def truncate_id(id) when is_binary(id) do
    String.slice(id, 0, 8) <> "..."
  end

  @doc """
  Returns pagination info text.
  """
  def pagination_info(page, per_page, total) do
    start_item = (page - 1) * per_page + 1
    end_item = min(page * per_page, total)

    "Showing #{start_item}-#{end_item} of #{total} tasks"
  end

  @doc """
  Returns the total number of pages.
  """
  def total_pages(total, per_page) do
    ceil(total / per_page)
  end
end
