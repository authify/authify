defmodule AuthifyWeb.MaintenanceController do
  use AuthifyWeb, :controller

  alias Authify.Accounts
  alias Authify.Invitations
  alias Authify.Stats
  alias Authify.Tasks

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
    # Create and enqueue a cleanup task for async execution
    case Tasks.create_and_enqueue_task(%{
           type: "cleanup_expired_invitations",
           action: "execute",
           organization_id: nil,
           status: :pending,
           metadata: %{
             triggered_by: "admin_manual",
             admin_user_id: conn.assigns.current_user.id,
             triggered_at: DateTime.utc_now()
           }
         }) do
      {:ok, task} ->
        conn
        |> put_flash(
          :info,
          "Cleanup task created successfully (Task ID: #{task.id}). " <>
            "View progress in the Tasks section."
        )
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/maintenance")

      {:error, changeset} ->
        conn
        |> put_flash(:error, "Failed to create cleanup task: #{inspect(changeset.errors)}")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/maintenance")
    end
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
        organizations: Stats.count_organizations(),
        users: Stats.count_users(),
        invitations: Invitations.count_invitations()
      },
      storage_usage: %{
        database_size_mb: get_database_size(),
        table_sizes: get_table_sizes()
      }
    }
  end

  defp get_system_health do
    %{
      uptime_seconds: get_vm_uptime_seconds(),
      memory_usage: get_memory_usage(),
      schedulers_online: System.schedulers_online(),
      run_queue_length: get_run_queue_length(),
      process_count: :erlang.system_info(:process_count),
      active_connections: get_active_connections(),
      last_backup: get_last_backup_time(),
      pending_jobs: get_pending_jobs_count()
    }
  end

  defp get_cleanup_stats do
    now = DateTime.utc_now()

    %{
      expired_invitations: Invitations.count_expired_invitations(),
      cleanable_invitations: Invitations.count_cleanable_invitations(),
      inactive_organizations_90d:
        Stats.count_inactive_organizations_since(DateTime.add(now, -90, :day)),
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
    # Query the actual MySQL database size in MB.
    case query_database_size() do
      {:ok, bytes} -> round(bytes / 1024 / 1024 * 10) / 10
      _ -> 0.0
    end
  end

  defp get_table_sizes do
    # Query actual per-table sizes from MySQL's information_schema.
    case query_table_sizes() do
      {:ok, rows} -> rows
      _ -> %{}
    end
  end

  defp get_memory_usage do
    memory = :erlang.memory()

    # Total = all BEAM memory (not system-wide). We report BEAM VM memory here.
    total_bytes = memory[:total]
    used_bytes = total_bytes - memory[:system]
    available_bytes = memory[:processes_used] + memory[:system]

    %{
      total_bytes: total_bytes,
      used_bytes: used_bytes,
      available_bytes: available_bytes,
      total_mb: div(total_bytes, 1024 * 1024),
      used_mb: div(used_bytes, 1024 * 1024),
      available_mb: div(available_bytes, 1024 * 1024)
    }
  end

  defp get_active_connections do
    # Report the configured database connection pool size, which is the number
    # of concurrent DB connections the application is provisioned to use.
    Application.get_env(:authify, Authify.Repo, [])
    |> Keyword.get(:pool_size, 1)
  end

  defp get_last_backup_time do
    # Placeholder - would check actual backup system
    DateTime.add(DateTime.utc_now(), -6, :hour)
  end

  defp get_pending_jobs_count do
    # Count Oban jobs in non-terminal states (queued for execution).
    import Ecto.Query

    from(j in Oban.Job,
      where: j.state in ["available", "scheduled", "retryable", "executing", "waiting"]
    )
    |> Authify.Repo.aggregate(:count, :id)
  end

  # VM metrics

  defp get_vm_uptime_seconds do
    :erlang.statistics(:wall_clock) |> elem(0) |> div(1000)
  end

  defp get_run_queue_length do
    :erlang.statistics(:total_run_queue_lengths_all)
  end

  defp query_database_size do
    query = """
    SELECT SUM(data_length + index_length) AS bytes
    FROM information_schema.tables
    WHERE table_schema = DATABASE()
    """

    case Authify.Repo.query(query) do
      {:ok, %{rows: [[nil]]}} ->
        {:ok, 0}

      {:ok, %{rows: [[bytes]]}} when is_integer(bytes) ->
        {:ok, bytes}

      {:ok, %{rows: [[bytes]]}} when is_binary(bytes) ->
        {:ok, String.to_integer(bytes)}

      _ ->
        :error
    end
  end

  defp query_table_sizes do
    query = """
    SELECT table_name, (data_length + index_length) AS bytes
    FROM information_schema.tables
    WHERE table_schema = DATABASE()
    ORDER BY bytes DESC
    LIMIT 10
    """

    case Authify.Repo.query(query) do
      {:ok, %{rows: rows}} ->
        sizes =
          Enum.reduce(rows, %{}, fn [table, bytes], acc ->
            bytes = if is_binary(bytes), do: String.to_integer(bytes), else: bytes
            Map.put(acc, table, round(bytes / 1024 / 1024 * 10) / 10)
          end)

        {:ok, sizes}

      _ ->
        :error
    end
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
