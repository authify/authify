defmodule Authify.Telemetry do
  @moduledoc """
  Telemetry metrics definitions for Authify.

  Exposes Prometheus-compatible metrics for monitoring:
  - HTTP request rates and latency
  - Database query performance
  - VM metrics (memory, processes)
  - Business metrics (OAuth flows, SAML authentications, etc.)
  """
  use Supervisor
  import Telemetry.Metrics

  def start_link(arg) do
    Supervisor.start_link(__MODULE__, arg, name: __MODULE__)
  end

  @impl true
  def init(_arg) do
    children = [
      # Telemetry poller will execute the given period measurements
      # every 10_000ms. Learn more here: https://hexdocs.pm/telemetry_metrics
      {:telemetry_poller, measurements: periodic_measurements(), period: 10_000},
      # Prometheus exporter - runs its own HTTP server on port 9568 at /metrics
      {TelemetryMetricsPrometheus, metrics: metrics()}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end

  def metrics do
    # Define histogram buckets for latency metrics (in milliseconds)
    buckets = [10, 50, 100, 250, 500, 1000, 2500, 5000, 10_000]

    [
      # Phoenix HTTP Metrics
      distribution("phoenix.endpoint.stop.duration",
        unit: {:native, :millisecond},
        tags: [:method, :route, :organization],
        tag_values: &get_route_info/1,
        description: "HTTP request duration",
        reporter_options: [buckets: buckets]
      ),
      counter("phoenix.endpoint.stop.duration",
        tags: [:method, :route, :status, :organization],
        tag_values: &get_route_info/1,
        description: "HTTP request count"
      ),
      counter("phoenix.error_rendered.duration",
        tags: [:status],
        description: "HTTP error count"
      ),

      # Database Metrics
      distribution("authify.repo.query.total_time",
        unit: {:native, :millisecond},
        tags: [:source],
        description: "Database query total time",
        reporter_options: [buckets: buckets]
      ),
      distribution("authify.repo.query.decode_time",
        unit: {:native, :millisecond},
        tags: [:source],
        description: "Database result decoding time",
        reporter_options: [buckets: buckets]
      ),
      distribution("authify.repo.query.query_time",
        unit: {:native, :millisecond},
        tags: [:source],
        description: "Database query execution time",
        reporter_options: [buckets: buckets]
      ),
      distribution("authify.repo.query.queue_time",
        unit: {:native, :millisecond},
        tags: [:source],
        description: "Database query queue time",
        reporter_options: [buckets: buckets]
      ),
      counter("authify.repo.query.total_time",
        tags: [:source, :result],
        tag_values: &get_query_result/1,
        description: "Database query count"
      ),

      # VM Metrics
      last_value("vm.memory.total", unit: :byte, description: "Total memory"),
      last_value("vm.memory.processes_used", unit: :byte, description: "Memory used by processes"),
      last_value("vm.memory.binary", unit: :byte, description: "Memory used by binaries"),
      last_value("vm.memory.ets", unit: :byte, description: "Memory used by ETS tables"),
      last_value("vm.total_run_queue_lengths.total",
        description: "Total run queue length"
      ),
      last_value("vm.total_run_queue_lengths.cpu",
        description: "CPU scheduler run queue length"
      ),
      last_value("vm.total_run_queue_lengths.io",
        description: "IO run queue length"
      ),
      last_value("vm.system_counts.process_count", description: "Number of processes"),
      last_value("vm.system_counts.atom_count", description: "Number of atoms"),
      last_value("vm.system_counts.port_count", description: "Number of ports"),

      # Business Metrics - OAuth
      counter("authify.oauth.authorization.count",
        tags: [:result],
        description: "OAuth authorization attempts"
      ),
      counter("authify.oauth.token.count",
        tags: [:grant_type, :result],
        description: "OAuth token issuance"
      ),
      distribution("authify.oauth.authorization.duration",
        unit: {:native, :millisecond},
        description: "OAuth authorization flow duration",
        reporter_options: [buckets: buckets]
      ),

      # Business Metrics - SAML
      counter("authify.saml.sso.count",
        tags: [:result],
        description: "SAML SSO authentication attempts"
      ),
      counter("authify.saml.slo.count",
        tags: [:result],
        description: "SAML Single Logout attempts"
      ),
      distribution("authify.saml.sso.duration",
        unit: {:native, :millisecond},
        description: "SAML SSO flow duration",
        reporter_options: [buckets: buckets]
      ),

      # Business Metrics - Users
      counter("authify.user.login.count",
        tags: [:result, :organization],
        description: "User login attempts"
      ),
      counter("authify.user.signup.count",
        tags: [:result],
        description: "User signup attempts"
      ),
      counter("authify.invitation.created.count",
        tags: [:organization],
        description: "Invitations created"
      ),
      counter("authify.invitation.accepted.count",
        tags: [:organization],
        description: "Invitations accepted"
      )
    ]
  end

  defp periodic_measurements do
    [
      # A module, function and arguments to be invoked periodically.
      {__MODULE__, :measure_users, []},
      {__MODULE__, :measure_organizations, []},
      {__MODULE__, :measure_oauth_apps, []},
      {__MODULE__, :measure_saml_providers, []}
    ]
  end

  # Periodic measurement functions
  def measure_users do
    import Ecto.Query

    total_users = Authify.Repo.aggregate(Authify.Accounts.User, :count, :id)

    active_users =
      Authify.Repo.aggregate(
        from(u in Authify.Accounts.User, where: u.active == true),
        :count,
        :id
      )

    :telemetry.execute([:authify, :users], %{total: total_users, active: active_users}, %{})
  end

  def measure_organizations do
    import Ecto.Query

    total_orgs = Authify.Repo.aggregate(Authify.Accounts.Organization, :count, :id)

    active_orgs =
      Authify.Repo.aggregate(
        from(o in Authify.Accounts.Organization, where: o.active == true),
        :count,
        :id
      )

    :telemetry.execute([:authify, :organizations], %{total: total_orgs, active: active_orgs}, %{})
  end

  def measure_oauth_apps do
    import Ecto.Query

    total_apps = Authify.Repo.aggregate(Authify.OAuth.Application, :count, :id)

    active_apps =
      Authify.Repo.aggregate(
        from(a in Authify.OAuth.Application, where: a.is_active == true),
        :count,
        :id
      )

    :telemetry.execute(
      [:authify, :oauth, :applications],
      %{total: total_apps, active: active_apps},
      %{}
    )
  end

  def measure_saml_providers do
    import Ecto.Query

    total_providers = Authify.Repo.aggregate(Authify.SAML.ServiceProvider, :count, :id)

    active_providers =
      Authify.Repo.aggregate(
        from(p in Authify.SAML.ServiceProvider, where: p.is_active == true),
        :count,
        :id
      )

    :telemetry.execute(
      [:authify, :saml, :providers],
      %{total: total_providers, active: active_providers},
      %{}
    )
  end

  # Helper functions to extract tags from telemetry events
  defp get_route_info(%{conn: conn} = metadata) do
    route =
      case Phoenix.Router.route_info(AuthifyWeb.Router, conn.method, conn.request_path, conn.host) do
        %{route: route} -> route
        %{} -> "unknown"
        :error -> "unknown"
      end

    # Extract organization from conn assigns if available
    organization =
      case Map.get(conn.assigns, :current_organization) do
        %{slug: slug} -> slug
        _ -> "none"
      end

    metadata
    |> Map.put(:route, route)
    |> Map.put(:method, conn.method)
    |> Map.put(:status, conn.status)
    |> Map.put(:organization, organization)
  end

  defp get_route_info(metadata), do: metadata

  defp get_query_result(%{result: result} = metadata) do
    Map.put(metadata, :result, query_result_status(result))
  end

  defp get_query_result(metadata), do: Map.put(metadata, :result, "unknown")

  defp query_result_status({:ok, _}), do: "ok"
  defp query_result_status({:error, _}), do: "error"
  defp query_result_status(_), do: "unknown"
end
