defmodule AuthifyWeb.AnalyticsController do
  use AuthifyWeb, :controller

  alias Authify.Accounts

  # All actions require being in the global organization
  def action(conn, _) do
    if conn.assigns.current_organization.slug != "authify-global" do
      conn
      |> put_flash(:error, "Access denied.")
      |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/dashboard")
      |> halt()
    else
      apply(__MODULE__, action_name(conn), [conn, conn.params])
    end
  end

  def index(conn, _params) do
    user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    # Get comprehensive system analytics
    analytics_data = %{
      system_overview: get_system_overview(),
      organization_stats: get_organization_analytics(),
      user_stats: get_user_analytics(),
      invitation_stats: get_invitation_analytics(),
      growth_metrics: get_growth_metrics(),
      activity_metrics: get_activity_metrics()
    }

    render(conn, :index,
      user: user,
      organization: organization,
      analytics: analytics_data
    )
  end

  # Private helper functions for analytics data

  defp get_system_overview do
    total_organizations = Accounts.count_organizations()
    active_organizations = Accounts.count_active_organizations()
    total_users = Accounts.count_users()
    global_admins = Accounts.count_global_admins()

    %{
      total_organizations: total_organizations,
      active_organizations: active_organizations,
      inactive_organizations: total_organizations - active_organizations,
      total_users: total_users,
      global_admins: global_admins,
      regular_users: total_users - global_admins
    }
  end

  defp get_organization_analytics do
    organizations = Accounts.list_organizations_with_stats()

    # Calculate organization metrics
    user_counts = Enum.map(organizations, &(&1.user_count || 0))

    %{
      largest_organization: Enum.max(user_counts, fn -> 0 end),
      smallest_organization: Enum.min(user_counts, fn -> 0 end),
      average_users_per_org:
        if(Enum.empty?(user_counts), do: 0, else: Enum.sum(user_counts) / length(user_counts)),
      organizations_by_size:
        Enum.group_by(organizations, fn org ->
          user_count = org.user_count || 0

          cond do
            user_count == 0 -> :empty
            user_count <= 5 -> :small
            user_count <= 20 -> :medium
            user_count <= 100 -> :large
            true -> :enterprise
          end
        end)
    }
  end

  defp get_user_analytics do
    recent_cutoff = DateTime.add(DateTime.utc_now(), -30, :day)

    %{
      new_users_last_30_days: Accounts.count_users_since(recent_cutoff),
      users_by_role: %{
        admin: Accounts.count_users_by_role_globally("admin"),
        user: Accounts.count_users_by_role_globally("user")
      },
      users_by_status: %{
        active: Accounts.count_active_users(),
        inactive: Accounts.count_inactive_users()
      }
    }
  end

  defp get_invitation_analytics do
    %{
      total_invitations: Accounts.count_invitations(),
      pending_invitations: Accounts.count_pending_invitations(),
      accepted_invitations: Accounts.count_accepted_invitations(),
      expired_invitations: Accounts.count_expired_invitations()
    }
  end

  defp get_growth_metrics do
    # Calculate growth over the last 6 months
    months = for i <- 5..0//-1, do: DateTime.add(DateTime.utc_now(), -i * 30, :day)

    monthly_data =
      Enum.map(months, fn date ->
        %{
          month: Calendar.strftime(date, "%B %Y"),
          organizations: Accounts.count_organizations_created_before(date),
          users: Accounts.count_users_created_before(date)
        }
      end)

    %{
      monthly_growth: monthly_data,
      organization_growth_rate: calculate_growth_rate(monthly_data, :organizations),
      user_growth_rate: calculate_growth_rate(monthly_data, :users)
    }
  end

  defp get_activity_metrics do
    last_24h = DateTime.add(DateTime.utc_now(), -1, :day)
    last_7d = DateTime.add(DateTime.utc_now(), -7, :day)
    last_30d = DateTime.add(DateTime.utc_now(), -30, :day)

    %{
      new_organizations_24h: Accounts.count_organizations_since(last_24h),
      new_organizations_7d: Accounts.count_organizations_since(last_7d),
      new_organizations_30d: Accounts.count_organizations_since(last_30d),
      new_users_24h: Accounts.count_users_since(last_24h),
      new_users_7d: Accounts.count_users_since(last_7d),
      new_users_30d: Accounts.count_users_since(last_30d),
      invitations_sent_7d: Accounts.count_invitations_since(last_7d),
      invitations_accepted_7d: Accounts.count_invitations_accepted_since(last_7d)
    }
  end

  defp calculate_growth_rate(monthly_data, field) do
    if length(monthly_data) >= 2 do
      current = Map.get(List.last(monthly_data), field, 0)
      previous = Map.get(Enum.at(monthly_data, -2), field, 0)

      if previous > 0 do
        Float.round((current - previous) / previous * 100, 2)
      else
        0.0
      end
    else
      0.0
    end
  end
end
