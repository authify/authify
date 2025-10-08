defmodule Authify.Configurations.Cache do
  @moduledoc """
  ETS-based cache for configuration settings.

  Provides a fast in-memory cache for configuration values to avoid
  repeated database queries. Uses a TTL-based expiration strategy to
  ensure configuration changes propagate within a reasonable timeframe.

  The cache is automatically started by the application supervisor.
  """

  use GenServer
  require Logger

  @cache_table :authify_configuration_cache
  # 60 seconds - config changes propagate within 1 minute
  @ttl 60_000
  # 2 minutes - clean up expired entries
  @cleanup_interval 120_000

  ## Client API

  @doc """
  Starts the cache GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Gets a cached configuration setting value.

  Returns `{:ok, value}` if found and not expired, `:miss` otherwise.

  ## Parameters

  - `configurable_type` - The type of entity (e.g., "Organization")
  - `configurable_id` - The ID of the entity
  - `setting_name` - The name of the setting (atom or string)

  ## Examples

      iex> Cache.get("Organization", 123, :auth_rate_limit)
      {:ok, 10}

      iex> Cache.get("Organization", 456, :unknown_setting)
      :miss
  """
  def get(configurable_type, configurable_id, setting_name) do
    key = cache_key(configurable_type, configurable_id, setting_name)
    now = System.monotonic_time(:millisecond)

    case :ets.lookup(@cache_table, key) do
      [{^key, value, expires_at}] when expires_at > now ->
        {:ok, value}

      _ ->
        :miss
    end
  end

  @doc """
  Puts a configuration setting value into the cache.

  The value will expire after the configured TTL (default 60 seconds).

  ## Parameters

  - `configurable_type` - The type of entity (e.g., "Organization")
  - `configurable_id` - The ID of the entity
  - `setting_name` - The name of the setting (atom or string)
  - `value` - The value to cache

  ## Examples

      iex> Cache.put("Organization", 123, :auth_rate_limit, 10)
      :ok
  """
  def put(configurable_type, configurable_id, setting_name, value) do
    key = cache_key(configurable_type, configurable_id, setting_name)
    expires_at = System.monotonic_time(:millisecond) + @ttl
    :ets.insert(@cache_table, {key, value, expires_at})
    :ok
  end

  @doc """
  Invalidates (removes) a specific setting from the cache.

  Use this when a configuration value is updated to force a fresh read.

  ## Examples

      iex> Cache.invalidate("Organization", 123, :auth_rate_limit)
      :ok
  """
  def invalidate(configurable_type, configurable_id, setting_name) do
    key = cache_key(configurable_type, configurable_id, setting_name)
    :ets.delete(@cache_table, key)
    :ok
  end

  @doc """
  Invalidates all settings for a specific entity.

  Useful when multiple settings are updated at once or when an entity is deleted.

  ## Examples

      iex> Cache.invalidate_all("Organization", 123)
      :ok
  """
  def invalidate_all(configurable_type, configurable_id) do
    # Match all keys for this entity
    pattern = {{configurable_type, configurable_id, :_}, :_, :_}
    :ets.match_delete(@cache_table, pattern)
    :ok
  end

  @doc """
  Clears the entire cache.

  Useful for testing or when you need to force a complete refresh.
  """
  def clear do
    :ets.delete_all_objects(@cache_table)
    :ok
  end

  ## GenServer Callbacks

  @impl true
  def init(_opts) do
    # Create the ETS table
    :ets.new(@cache_table, [
      :set,
      :named_table,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    Logger.info("Configuration cache started with TTL: #{@ttl}ms")

    # Schedule periodic cleanup of expired entries
    schedule_cleanup()

    {:ok, %{}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_expired()
    schedule_cleanup()
    {:noreply, state}
  end

  ## Private Functions

  defp cache_key(configurable_type, configurable_id, setting_name) do
    # Normalize setting_name to string for consistency
    setting_name_str = to_string(setting_name)
    {configurable_type, configurable_id, setting_name_str}
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end

  defp cleanup_expired do
    now = System.monotonic_time(:millisecond)

    # Delete all entries where expires_at <= now
    deleted =
      :ets.select_delete(@cache_table, [
        {{:_, :_, :"$1"}, [{:"=<", :"$1", now}], [true]}
      ])

    if deleted > 0 do
      Logger.debug("Cleaned up #{deleted} expired configuration cache entries")
    end

    deleted
  end
end
