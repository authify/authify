defmodule AuthifyWeb.HealthController do
  use AuthifyWeb, :controller

  @moduledoc """
  Provides health check endpoints for monitoring and container orchestration.

  The health endpoint is used by Kubernetes probes (liveness/readiness) and
  load balancers to determine if the application is healthy and ready to serve traffic.

  ## Security Features

  - **Response Caching**: Health check results are cached for 1 second to prevent
    database connection pool exhaustion from repeated requests or potential DoS attacks.
  - **Fast Response**: Cached responses return immediately without DB queries.
  - **Attack Mitigation**: Even under heavy load, DB queries are limited to ~1/second.
  """

  @cache_table :health_check_cache
  @cache_ttl_seconds 1

  @doc """
  Health check endpoint that verifies:
  - Application is running
  - Database connectivity (cached for #{@cache_ttl_seconds} second)

  Returns 200 OK if healthy, 503 Service Unavailable if unhealthy.
  """
  def index(conn, _params) do
    case get_cached_health_status() do
      {:ok, status} ->
        respond_with_status(conn, status)

      :cache_miss ->
        status = check_database_status()
        cache_health_status(status)
        respond_with_status(conn, status)
    end
  end

  defp respond_with_status(conn, {:healthy, timestamp}) do
    json(conn, %{
      status: "healthy",
      database: "connected",
      timestamp: timestamp,
      cached: true
    })
  end

  defp respond_with_status(conn, {:unhealthy, reason, timestamp}) do
    conn
    |> put_status(:service_unavailable)
    |> json(%{
      status: "unhealthy",
      database: "disconnected",
      error: reason,
      timestamp: timestamp,
      cached: true
    })
  end

  defp get_cached_health_status do
    ensure_cache_table_exists()

    case :ets.lookup(@cache_table, :health_status) do
      [{:health_status, status, cached_at}] ->
        if cache_fresh?(cached_at) do
          {:ok, status}
        else
          :cache_miss
        end

      [] ->
        :cache_miss
    end
  rescue
    ArgumentError ->
      # Table doesn't exist, will be created on next call
      :cache_miss
  end

  defp cache_health_status(status) do
    ensure_cache_table_exists()
    :ets.insert(@cache_table, {:health_status, status, System.monotonic_time(:second)})
  rescue
    ArgumentError ->
      # If table creation fails due to race condition, ignore
      :ok
  end

  defp cache_fresh?(cached_at) do
    now = System.monotonic_time(:second)
    now - cached_at < @cache_ttl_seconds
  end

  defp ensure_cache_table_exists do
    unless :ets.whereis(@cache_table) != :undefined do
      :ets.new(@cache_table, [:set, :public, :named_table])
    end
  rescue
    ArgumentError ->
      # Table already exists (race condition), ignore
      :ok
  end

  defp check_database_status do
    # Simple query to verify database connectivity
    Authify.Repo.query("SELECT 1")
    {:healthy, DateTime.utc_now() |> DateTime.to_iso8601()}
  rescue
    error -> {:unhealthy, inspect(error), DateTime.utc_now() |> DateTime.to_iso8601()}
  end
end
