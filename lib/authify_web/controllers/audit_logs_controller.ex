defmodule AuthifyWeb.AuditLogsController do
  use AuthifyWeb, :controller

  alias Authify.Accounts
  alias Authify.AuditLog

  def index(conn, params) do
    user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    # Only allow admins and super admins to view audit logs
    if Accounts.User.admin?(user, organization.id) || Accounts.User.super_admin?(user) do
      # Parse filtering params
      {event_type, category} = parse_event_filter(params["event_filter"])
      user_id = params["user_id"]
      actor_name = params["actor_name"]
      outcome = params["outcome"]
      date_from = parse_date(params["date_from"])
      date_to = parse_date(params["date_to"])

      # Build filter options
      filter_opts = [
        event_type: event_type,
        category: category,
        user_id: user_id,
        actor_name: actor_name,
        outcome: outcome,
        date_from: date_from,
        date_to: date_to,
        organization_id: organization.id,
        limit: 100
      ]

      # Get filtered events
      events = AuditLog.list_events(filter_opts)

      # Get available filter options
      event_types = AuditLog.Event.event_types()
      outcomes = AuditLog.Event.outcome_types()

      # Get users in organization for user filter dropdown
      users =
        if organization.slug == "authify-global" do
          Accounts.list_global_admins()
        else
          Accounts.list_users_filtered(organization.id, [])
        end

      render(conn, :index,
        user: user,
        organization: organization,
        events: events,
        event_types: event_types,
        outcomes: outcomes,
        users: users,
        filters: %{
          event_type: event_type,
          category: category,
          user_id: user_id,
          actor_name: actor_name,
          outcome: outcome,
          date_from: params["date_from"],
          date_to: params["date_to"]
        }
      )
    else
      conn
      |> put_flash(:error, "You must be an administrator to view audit logs.")
      |> redirect(to: ~p"/#{organization.slug}/dashboard")
      |> halt()
    end
  end

  def show(conn, %{"id" => id}) do
    user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    # Only allow admins and super admins to view audit logs
    if Accounts.User.admin?(user, organization.id) || Accounts.User.super_admin?(user) do
      event = AuditLog.get_event!(id)

      # Verify event belongs to current organization
      if event.organization_id == organization.id do
        # Load associated user if present
        event = AuditLog.preload_event(event)

        render(conn, :show,
          user: user,
          organization: organization,
          event: event
        )
      else
        conn
        |> put_status(:not_found)
        |> put_view(AuthifyWeb.ErrorHTML)
        |> render(:"404")
        |> halt()
      end
    else
      conn
      |> put_flash(:error, "You must be an administrator to view audit logs.")
      |> redirect(to: ~p"/#{organization.slug}/dashboard")
      |> halt()
    end
  end

  defp parse_date(nil), do: nil

  defp parse_date(date_string) do
    case Date.from_iso8601(date_string) do
      {:ok, date} -> date
      {:error, _} -> nil
    end
  end

  # Parse the event_filter parameter which can be either:
  # - A category like "cat_scim", "cat_auth", "cat_user"
  # - A specific event type
  # - nil/empty
  defp parse_event_filter(nil), do: {nil, nil}
  defp parse_event_filter(""), do: {nil, nil}

  defp parse_event_filter("cat_" <> category) do
    {nil, category}
  end

  defp parse_event_filter(event_type) do
    {event_type, nil}
  end
end
