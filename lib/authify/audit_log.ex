defmodule Authify.AuditLog do
  @moduledoc """
  The AuditLog context for security and authentication events.

  Provides functions to log and query audit events for security monitoring,
  compliance, and debugging purposes.

  ## Scaling Notes

  Currently uses MySQL for audit storage. This is suitable for most deployments
  up to ~10k events/second. Future scaling options include:
  - Table partitioning by date (for >10M rows)
  - Archival to cold storage (S3, etc.)
  - Migration to time-series DB (ClickHouse, TimescaleDB) for extreme scale
  """

  import Ecto.Query, warn: false

  alias Authify.AuditLog.Event
  alias Authify.Repo

  @doc """
  Logs a security or authentication event.

  ## Parameters

    * `event_type` - The type of event (atom or string from Event.event_types/0)
    * `attrs` - Map containing:
      * `:organization_id` - Required. The organization this event belongs to
      * `:actor_type` - Required. One of: "user", "api_client", "system"
      * `:outcome` - Required. One of: "success", "failure", "denied"
      * `:user_id` - Optional. The user who performed the action (if actor_type is "user")
      * `:actor_name` - Optional. Display name for the actor (useful for API clients)
      * `:resource_type` - Optional. The type of resource affected
      * `:resource_id` - Optional. The ID of the resource affected
      * `:ip_address` - Optional. IP address of the actor
      * `:user_agent` - Optional. User agent string
      * `:metadata` - Optional. Map of additional event-specific data

  ## Examples

      iex> log_event(:login_success, %{
      ...>   organization_id: 1,
      ...>   user_id: 123,
      ...>   actor_type: "user",
      ...>   outcome: "success",
      ...>   ip_address: "192.168.1.1"
      ...> })
      {:ok, %Event{}}

      iex> log_event(:oauth_token_granted, %{
      ...>   organization_id: 1,
      ...>   actor_type: "api_client",
      ...>   actor_name: "Mobile App",
      ...>   outcome: "success",
      ...>   metadata: %{client_id: "abc123", scopes: ["read", "write"]}
      ...> })
      {:ok, %Event{}}

  """
  def log_event(event_type, attrs) when is_atom(event_type) do
    log_event(to_string(event_type), attrs)
  end

  def log_event(event_type, attrs) when is_binary(event_type) do
    attrs = Map.put(attrs, :event_type, event_type)

    %Event{}
    |> Event.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Logs an event asynchronously without waiting for the result.

  Useful for high-throughput scenarios where you don't want to block on audit logging.
  Errors are logged but not propagated to the caller.

  In test environment, falls back to synchronous logging to avoid Ecto sandbox issues.

  ## Examples

      iex> log_event_async(:login_success, %{organization_id: 1, ...})
      :ok

  """
  def log_event_async(event_type, attrs) do
    # In test environment, use synchronous logging to avoid sandbox issues
    if Mix.env() == :test do
      case log_event(event_type, attrs) do
        {:ok, _event} ->
          :ok

        {:error, changeset} ->
          require Logger
          Logger.error("Failed to log audit event: #{inspect(changeset)}")
          :ok
      end
    else
      Task.start(fn ->
        case log_event(event_type, attrs) do
          {:ok, _event} ->
            :ok

          {:error, changeset} ->
            require Logger
            Logger.error("Failed to log audit event: #{inspect(changeset)}")
        end
      end)
    end

    :ok
  end

  @doc """
  Lists audit events with optional filtering.

  ## Options

    * `:organization_id` - Filter by organization (required for non-global admins)
    * `:user_id` - Filter by user
    * `:event_type` - Filter by event type
    * `:actor_type` - Filter by actor type
    * `:outcome` - Filter by outcome
    * `:resource_type` - Filter by resource type
    * `:resource_id` - Filter by resource ID
    * `:from_date` - Filter events after this datetime
    * `:to_date` - Filter events before this datetime
    * `:limit` - Maximum number of results (default: 100)
    * `:offset` - Number of results to skip (default: 0)
    * `:order_by` - Order results (default: [desc: :inserted_at])

  ## Examples

      iex> list_events(organization_id: 1, event_type: "login_success", limit: 50)
      [%Event{}, ...]

  """
  def list_events(opts \\ []) do
    Event
    |> apply_filters(opts)
    |> apply_pagination(opts)
    |> Repo.all()
  end

  @doc """
  Counts audit events matching the given filters.

  Accepts the same filter options as `list_events/1`.

  ## Examples

      iex> count_events(organization_id: 1, event_type: "login_failure")
      42

  """
  def count_events(opts \\ []) do
    Event
    |> apply_filters(opts)
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Gets a single event by ID.

  ## Examples

      iex> get_event(123, organization_id: 1)
      {:ok, %Event{}}

      iex> get_event(999, organization_id: 1)
      {:error, :not_found}

  """
  def get_event(id, opts \\ []) do
    query =
      Event
      |> where([e], e.id == ^id)
      |> apply_filters(opts)

    case Repo.one(query) do
      nil -> {:error, :not_found}
      event -> {:ok, event}
    end
  end

  @doc """
  Gets event statistics for a given time period.

  Returns counts grouped by event type, outcome, etc.

  ## Examples

      iex> get_event_stats(organization_id: 1, from_date: ~U[2025-10-01 00:00:00Z])
      %{
        total: 1000,
        by_event_type: %{"login_success" => 800, "login_failure" => 200},
        by_outcome: %{"success" => 850, "failure" => 150}
      }

  """
  def get_event_stats(opts \\ []) do
    base_query = apply_filters(Event, opts)

    %{
      total: Repo.aggregate(base_query, :count, :id),
      by_event_type: count_by_field(base_query, :event_type),
      by_outcome: count_by_field(base_query, :outcome),
      by_actor_type: count_by_field(base_query, :actor_type)
    }
  end

  # Private helper functions

  defp apply_filters(query, opts) do
    Enum.reduce(opts, query, fn
      {:organization_id, org_id}, q when not is_nil(org_id) ->
        where(q, [e], e.organization_id == ^org_id)

      {:user_id, user_id}, q when not is_nil(user_id) ->
        where(q, [e], e.user_id == ^user_id)

      {:event_type, event_type}, q when not is_nil(event_type) ->
        where(q, [e], e.event_type == ^event_type)

      {:actor_type, actor_type}, q when not is_nil(actor_type) ->
        where(q, [e], e.actor_type == ^actor_type)

      {:outcome, outcome}, q when not is_nil(outcome) ->
        where(q, [e], e.outcome == ^outcome)

      {:resource_type, resource_type}, q when not is_nil(resource_type) ->
        where(q, [e], e.resource_type == ^resource_type)

      {:resource_id, resource_id}, q when not is_nil(resource_id) ->
        where(q, [e], e.resource_id == ^resource_id)

      {:from_date, from_date}, q when not is_nil(from_date) ->
        where(q, [e], e.inserted_at >= ^from_date)

      {:to_date, to_date}, q when not is_nil(to_date) ->
        where(q, [e], e.inserted_at <= ^to_date)

      _other, q ->
        q
    end)
  end

  defp apply_pagination(query, opts) do
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)
    order_by = Keyword.get(opts, :order_by, desc: :inserted_at)

    query
    |> limit(^limit)
    |> offset(^offset)
    |> order_by(^order_by)
  end

  defp count_by_field(query, field) do
    query
    |> group_by([e], field(e, ^field))
    |> select([e], {field(e, ^field), count(e.id)})
    |> Repo.all()
    |> Map.new()
  end

  @doc """
  Helper to extract actor information from a Phoenix connection.

  ## Examples

      iex> actor_from_conn(conn, current_user)
      %{
        actor_type: "user",
        user_id: 123,
        actor_name: "John Doe",
        ip_address: "192.168.1.1",
        user_agent: "Mozilla/5.0..."
      }

  """
  def actor_from_conn(conn, user \\ nil) do
    %{
      actor_type: if(user, do: "user", else: "system"),
      user_id: user && user.id,
      actor_name: user && "#{user.first_name} #{user.last_name}",
      ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
      user_agent: Plug.Conn.get_req_header(conn, "user-agent") |> List.first()
    }
  end

  @doc """
  Helper to extract actor information from an API client.

  ## Examples

      iex> actor_from_api_client(oauth_client, conn)
      %{
        actor_type: "api_client",
        actor_name: "Mobile App",
        ip_address: "192.168.1.1",
        metadata: %{client_id: "abc123"}
      }

  """
  def actor_from_api_client(client, conn) do
    %{
      actor_type: "api_client",
      actor_name: client.name,
      ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
      user_agent: Plug.Conn.get_req_header(conn, "user-agent") |> List.first(),
      metadata: %{client_id: client.client_id}
    }
  end
end
