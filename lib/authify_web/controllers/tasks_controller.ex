defmodule AuthifyWeb.TasksController do
  use AuthifyWeb, :controller

  alias Authify.{Accounts, Tasks}

  plug :require_global_admin

  def index(conn, params) do
    user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    # Parse pagination
    page = String.to_integer(params["page"] || "1")
    per_page = String.to_integer(params["per_page"] || "25")

    # Parse filters
    filter_opts = build_filter_opts(params)

    # Get tasks (global, not scoped to organization since this is authify-global)
    {tasks, total} =
      Tasks.list_all_tasks(Keyword.merge(filter_opts, page: page, per_page: per_page))

    # Get organizations for filter dropdown
    organizations = Accounts.list_organizations()

    # Get available statuses grouped by category
    status_groups = %{
      "Active" => Authify.Tasks.Task.active_states(),
      "Transitioning" => Authify.Tasks.Task.transitioning_states(),
      "Terminal" => Authify.Tasks.Task.terminal_states()
    }

    render(conn, :index,
      user: user,
      organization: organization,
      tasks: tasks,
      total: total,
      page: page,
      per_page: per_page,
      organizations: organizations,
      status_groups: status_groups,
      filters: build_current_filters(params),
      current_page: "tasks"
    )
  end

  # --- Private Functions ---

  defp require_global_admin(conn, _opts) do
    organization = conn.assigns.current_organization

    if organization.slug == "authify-global" do
      conn
    else
      conn
      |> put_flash(:error, "Tasks are only accessible from the global organization.")
      |> redirect(to: ~p"/#{organization.slug}/dashboard")
      |> halt()
    end
  end

  defp build_filter_opts(params) do
    []
    |> maybe_add_filter(:status, parse_status(params["status"]))
    |> maybe_add_filter(:type, params["type"])
    |> maybe_add_filter(:action, params["action"])
    |> maybe_add_filter(:organization_id, parse_integer(params["organization_id"]))
  end

  defp maybe_add_filter(opts, _key, nil), do: opts
  defp maybe_add_filter(opts, _key, ""), do: opts
  defp maybe_add_filter(opts, key, value), do: Keyword.put(opts, key, value)

  defp parse_status(nil), do: nil
  defp parse_status(""), do: nil

  defp parse_status(status_string) do
    String.to_existing_atom(status_string)
  rescue
    ArgumentError -> nil
  end

  defp parse_integer(nil), do: nil
  defp parse_integer(""), do: nil

  defp parse_integer(value) do
    String.to_integer(value)
  rescue
    ArgumentError -> nil
  end

  defp build_current_filters(params) do
    %{
      status: params["status"],
      type: params["type"],
      action: params["action"],
      organization_id: params["organization_id"]
    }
  end
end
