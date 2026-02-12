defmodule AuthifyWeb.TaskLive.Show do
  use AuthifyWeb, :live_view

  alias Authify.Security.Sanitizer
  alias Authify.Tasks

  # 3 seconds
  @refresh_interval 3_000

  on_mount {AuthifyWeb.LiveAuth, :ensure_authenticated}
  on_mount {AuthifyWeb.LiveAuth, :put_current_organization}

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    # Ensure user is in global organization
    organization = socket.assigns.current_organization

    if organization.slug != "authify-global" do
      {:ok,
       socket
       |> put_flash(:error, "Tasks are only accessible from the global organization.")
       |> redirect(to: ~p"/#{organization.slug}/dashboard")}
    else
      task = load_task(id)

      # Set up auto-refresh if task is not in terminal state
      if connected?(socket) and not terminal?(task) do
        Process.send_after(self(), :refresh, @refresh_interval)
      end

      {:ok,
       socket
       |> assign(:task, task)
       |> assign(:correlated_tasks, load_correlated_tasks(task))
       |> assign(:current_page, "tasks")}
    end
  end

  @impl true
  def handle_params(_params, _uri, socket) do
    {:noreply, socket}
  end

  @impl true
  def handle_info(:refresh, socket) do
    task = load_task(socket.assigns.task.id)

    # Schedule next refresh if still not terminal
    if not terminal?(task) do
      Process.send_after(self(), :refresh, @refresh_interval)
    end

    {:noreply,
     socket
     |> assign(:task, task)
     |> assign(:correlated_tasks, load_correlated_tasks(task))}
  end

  @impl true
  def handle_event("cancel", _params, socket) do
    task = socket.assigns.task

    case Tasks.cancel_task(task) do
      {:ok, _cancelled_task} ->
        {:noreply,
         socket
         |> put_flash(:info, "Task successfully cancelled.")
         |> assign(:task, load_task(task.id))}

      {:error, {:invalid_transition, from_state, _to_state}} ->
        {:noreply,
         socket
         |> put_flash(
           :error,
           "Cannot cancel task in #{from_state} state. Only active or waiting tasks can be cancelled."
         )}

      {:error, _reason} ->
        {:noreply,
         socket
         |> put_flash(:error, "Failed to cancel task. Please try again.")}
    end
  end

  defp load_task(id) do
    Tasks.get_task!(id)
    |> Authify.Repo.preload([:organization, :parent, :children, logs: []])
  end

  defp load_correlated_tasks(task) do
    if task.correlation_id do
      Tasks.list_correlated_tasks(task.correlation_id)
    else
      []
    end
  end

  defp terminal?(task) do
    task.status in Authify.Tasks.Task.terminal_states()
  end

  # Helper functions for template
  def cancellable?(task) do
    task.status in [:pending, :scheduled, :running, :waiting, :retrying]
  end

  def format_status(status) do
    status
    |> Atom.to_string()
    |> String.replace("_", " ")
    |> String.capitalize()
  end

  def status_badge_class(status) when status in [:completed], do: "badge bg-success"
  def status_badge_class(status) when status in [:failed, :timed_out], do: "badge bg-danger"
  def status_badge_class(status) when status in [:cancelled], do: "badge bg-secondary"
  def status_badge_class(status) when status in [:running], do: "badge bg-primary"

  def status_badge_class(status) when status in [:pending, :scheduled, :waiting],
    do: "badge bg-info"

  def status_badge_class(status) when status in [:retrying], do: "badge bg-warning"
  def status_badge_class(_), do: "badge bg-secondary"

  def format_datetime(nil), do: "N/A"

  def format_datetime(datetime) do
    Calendar.strftime(datetime, "%B %d, %Y at %I:%M %p UTC")
  end

  def format_log_timestamp(nil), do: "N/A"

  def format_log_timestamp(datetime) do
    # Compact syslog-style format: "Feb 11 14:45:23"
    Calendar.strftime(datetime, "%b %d %H:%M:%S")
  end

  def format_json(nil), do: "{}"
  def format_json(map) when map == %{}, do: "{}"

  def format_json(map) do
    Jason.encode!(map, pretty: true)
  end

  def truncate_id(id) when is_binary(id) do
    String.slice(id, 0..7) <> "..."
  end

  def truncate_id(_), do: "N/A"

  @doc """
  Sanitizes sensitive data from content before displaying in UI.
  Delegates to Authify.Security.Sanitizer for actual sanitization.
  """
  def sanitize_for_display(content), do: Sanitizer.sanitize(content)
end
