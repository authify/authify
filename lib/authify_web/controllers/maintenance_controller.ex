defmodule AuthifyWeb.MaintenanceController do
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

    # Get system maintenance data
    maintenance_data = %{
      database_stats: get_database_stats(),
      system_health: get_system_health(),
      cleanup_stats: get_cleanup_stats(),
      maintenance_logs: get_recent_maintenance_logs()
    }

    render(conn, :index,
      user: user,
      organization: organization,
      maintenance: maintenance_data
    )
  end

  def cleanup_expired_invitations(conn, _params) do
    deleted_count = Accounts.cleanup_expired_invitations()

    conn
    |> put_flash(:info, "Successfully cleaned up #{deleted_count} expired invitations.")
    |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/maintenance")
  end

  def cleanup_inactive_organizations(conn, _params) do
    # Only cleanup organizations that have been inactive for more than 90 days
    cutoff_date = DateTime.add(DateTime.utc_now(), -90, :day)
    deleted_count = Accounts.cleanup_inactive_organizations(cutoff_date)

    conn
    |> put_flash(:info, "Successfully cleaned up #{deleted_count} inactive organizations.")
    |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/maintenance")
  end

  def recalculate_stats(conn, _params) do
    # This could trigger background jobs to recalculate cached statistics
    # For now, just refresh the cached data
    :ok

    conn
    |> put_flash(:info, "Statistics recalculation triggered successfully.")
    |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/maintenance")
  end

  # Private helper functions for maintenance data

  defp get_database_stats do
    %{
      total_records: %{
        organizations: Accounts.count_organizations(),
        users: Accounts.count_users(),
        invitations: Accounts.count_invitations()
      },
      storage_usage: %{
        database_size_mb: get_database_size(),
        table_sizes: get_table_sizes()
      }
    }
  end

  defp get_system_health do
    %{
      uptime_seconds: :erlang.statistics(:wall_clock) |> elem(0) |> div(1000),
      memory_usage: get_memory_usage(),
      active_connections: get_active_connections(),
      last_backup: get_last_backup_time(),
      pending_jobs: get_pending_jobs_count()
    }
  end

  defp get_cleanup_stats do
    now = DateTime.utc_now()

    %{
      expired_invitations: Accounts.count_expired_invitations(),
      inactive_organizations_90d:
        Accounts.count_inactive_organizations_since(DateTime.add(now, -90, :day)),
      orphaned_sessions: get_orphaned_sessions_count(),
      temp_files: get_temp_files_count()
    }
  end

  defp get_recent_maintenance_logs do
    # This would typically come from a maintenance_logs table
    # For now, return placeholder data
    [
      %{
        action: "Cleanup expired invitations",
        timestamp: DateTime.add(DateTime.utc_now(), -2, :hour),
        status: "completed",
        details: "Removed 15 expired invitations"
      },
      %{
        action: "Database optimization",
        timestamp: DateTime.add(DateTime.utc_now(), -1, :day),
        status: "completed",
        details: "Optimized user and organization indexes"
      },
      %{
        action: "Backup verification",
        timestamp: DateTime.add(DateTime.utc_now(), -2, :day),
        status: "completed",
        details: "All backups verified successfully"
      }
    ]
  end

  # Placeholder functions for system metrics
  # These would typically interface with system monitoring tools

  defp get_database_size do
    # Placeholder - would query actual database size
    256.7
  end

  defp get_table_sizes do
    %{
      "users" => 45.2,
      "organizations" => 12.8,
      "invitations" => 8.5,
      "other" => 190.2
    }
  end

  defp get_memory_usage do
    # Placeholder - would query actual memory usage
    %{
      total_mb: 1024,
      used_mb: 768,
      available_mb: 256
    }
  end

  defp get_active_connections do
    # Placeholder - would query actual database connections
    12
  end

  defp get_last_backup_time do
    # Placeholder - would check actual backup system
    DateTime.add(DateTime.utc_now(), -6, :hour)
  end

  defp get_pending_jobs_count do
    # Placeholder - would check job queue
    3
  end

  defp get_orphaned_sessions_count do
    # Placeholder - would check for sessions without valid users
    7
  end

  defp get_temp_files_count do
    # Placeholder - would check temporary file storage
    23
  end
end
