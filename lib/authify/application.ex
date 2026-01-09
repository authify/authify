defmodule Authify.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children =
      [
        Authify.Repo,
        # Cluster formation - use libcluster for Kubernetes, DNSCluster for fallback
        {Cluster.Supervisor,
         [Application.get_env(:libcluster, :topologies, []), [name: Authify.ClusterSupervisor]]},
        Authify.RateLimit,
        Authify.Configurations.Cache,
        {Phoenix.PubSub, name: Authify.PubSub}
      ] ++
        prometheus_children() ++
        [
          # Start a worker by calling: Authify.Worker.start_link(arg)
          # {Authify.Worker, arg},
          # Start to serve requests, typically the last entry
          AuthifyWeb.Endpoint
        ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Authify.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Start Prometheus metrics based on runtime configuration
  # Defaults to enabled, but can be disabled with ENABLE_METRICS=false
  # Always disabled in test environment
  defp prometheus_children do
    if Application.get_env(:authify, :metrics_enabled, true) do
      [AuthifyWeb.Telemetry, Authify.Telemetry]
    else
      []
    end
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    AuthifyWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
