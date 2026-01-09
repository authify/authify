import Config

# config/runtime.exs is executed for all environments, including
# during releases. It is executed after compilation and before the
# system starts, so it is typically used to load production configuration
# and secrets from environment variables or elsewhere. Do not define
# any compile-time configuration in here, as it won't be applied.
# The block below contains prod specific runtime configuration.

# ## Using releases
#
# If you use `mix release`, you need to explicitly enable the server
# by passing the PHX_SERVER=true when you start it:
#
#     PHX_SERVER=true bin/authify start
#
# Alternatively, you can use `mix phx.gen.release` to generate a `bin/server`
# script that automatically sets the env var above.
if System.get_env("PHX_SERVER") do
  config :authify, AuthifyWeb.Endpoint, server: true
end

# ## Metrics Configuration
#
# Enable or disable Prometheus metrics collection. Metrics are exposed on port 9568 at /metrics.
# Set ENABLE_METRICS=false to disable metrics collection and save memory/CPU resources.
# Defaults to true (enabled) unless already configured (e.g., in test environment).
if is_nil(Application.get_env(:authify, :metrics_enabled)) do
  config :authify, :metrics_enabled, System.get_env("ENABLE_METRICS", "true") == "true"
end

# ## Encryption Configuration
#
# Password used to encrypt sensitive fields (private keys, tokens, etc.) before storing in the database.
# This prevents sensitive data from being stored in plaintext.
# Generate a strong password using: mix phx.gen.secret
# Set via environment variable: ENCRYPTION_PASSWORD
config :authify,
       :encryption_password,
       System.get_env("ENCRYPTION_PASSWORD") ||
         System.get_env("SECRET_KEY_BASE") ||
         "dev_encryption_password_change_in_production"

# ## API Documentation Configuration
#
# Base URL for API documentation and OpenAPI spec generation.
# Set via environment variable: API_BASE_URL
#
# If not set, the API docs will auto-detect the URL from incoming requests,
# checking X-Forwarded-Proto header for proper HTTPS detection behind proxies.
#
# Examples:
#   API_BASE_URL=https://api.authify.pw
#   API_BASE_URL=https://auth.example.com
if api_base_url = System.get_env("API_BASE_URL") do
  config :authify, :api_base_url, api_base_url
end

# ## Cluster Configuration
#
# Configure libcluster for distributed Elixir in production (Kubernetes)
# Uses DNS-based discovery via headless service (no RBAC required)
# In development, clustering is disabled
if config_env() == :prod do
  # Kubernetes.DNS strategy - simple DNS-based discovery using headless service
  # Requires: POD_IP environment variable and headless service
  # Node names will be: authify@<pod_ip>
  if System.get_env("POD_IP") do
    config :libcluster,
      topologies: [
        k8s: [
          strategy: Cluster.Strategy.Kubernetes.DNS,
          config: [
            service: System.get_env("CLUSTER_SERVICE_NAME") || "authify-internal",
            application_name: "authify",
            polling_interval: 10_000
          ]
        ]
      ]
  end

  # Enable distributed rate limiting in production using Phoenix.PubSub
  config :hammer,
    backend: {
      Hammer.Backend.ETS,
      [
        expiry_ms: 60_000 * 60 * 4,
        cleanup_interval_ms: 60_000 * 10,
        pubsub: [
          pool_size: 4,
          pool_name: Authify.PubSub
        ]
      ]
    }
end

if config_env() == :prod do
  database_url =
    System.get_env("DATABASE_URL") ||
      raise """
      environment variable DATABASE_URL is missing.
      For example: ecto://USER:PASS@HOST/DATABASE
      """

  maybe_ipv6 = if System.get_env("ECTO_IPV6") in ~w(true 1), do: [:inet6], else: []

  config :authify, Authify.Repo,
    # ssl: true,
    url: database_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10"),
    # For machines with several cores, consider starting multiple pools of `pool_size`
    # pool_count: 4,
    socket_options: maybe_ipv6

  # The secret key base is used to sign/encrypt cookies and other secrets.
  # A default value is used in config/dev.exs and config/test.exs but you
  # want to use a different value for prod and you most likely don't want
  # to check this value into version control, so we use an environment
  # variable instead.
  secret_key_base =
    System.get_env("SECRET_KEY_BASE") ||
      raise """
      environment variable SECRET_KEY_BASE is missing.
      You can generate one by calling: mix phx.gen.secret
      """

  host = System.get_env("PHX_HOST") || "example.com"
  port = String.to_integer(System.get_env("PORT") || "4000")

  config :authify, :dns_cluster_query, System.get_env("DNS_CLUSTER_QUERY")

  config :authify, AuthifyWeb.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    http: [
      # Enable IPv6 and bind on all interfaces.
      # Set it to  {0, 0, 0, 0, 0, 0, 0, 1} for local network only access.
      # See the documentation on https://hexdocs.pm/bandit/Bandit.html#t:options/0
      # for details about using IPv6 vs IPv4 and loopback vs public addresses.
      ip: {0, 0, 0, 0, 0, 0, 0, 0},
      port: port
    ],
    secret_key_base: secret_key_base

  # ## SSL Support
  #
  # To get SSL working, you will need to add the `https` key
  # to your endpoint configuration:
  #
  #     config :authify, AuthifyWeb.Endpoint,
  #       https: [
  #         ...,
  #         port: 443,
  #         cipher_suite: :strong,
  #         keyfile: System.get_env("SOME_APP_SSL_KEY_PATH"),
  #         certfile: System.get_env("SOME_APP_SSL_CERT_PATH")
  #       ]
  #
  # The `cipher_suite` is set to `:strong` to support only the
  # latest and more secure SSL ciphers. This means old browsers
  # and clients may not be supported. You can set it to
  # `:compatible` for wider support.
  #
  # `:keyfile` and `:certfile` expect an absolute path to the key
  # and cert in disk or a relative path inside priv, for example
  # "priv/ssl/server.key". For all supported SSL configuration
  # options, see https://hexdocs.pm/plug/Plug.SSL.html#configure/1
  #
  # We also recommend setting `force_ssl` in your config/prod.exs,
  # ensuring no data is ever sent via http, always redirecting to https:
  #
  #     config :authify, AuthifyWeb.Endpoint,
  #       force_ssl: [hsts: true]
  #
  # Check `Plug.SSL` for all available options in `force_ssl`.

  # ## Configuring the mailer
  #
  # In production you need to configure the mailer to use a different adapter.
  # Here is an example configuration for Mailgun:
  #
  #     config :authify, Authify.Mailer,
  #       adapter: Swoosh.Adapters.Mailgun,
  #       api_key: System.get_env("MAILGUN_API_KEY"),
  #       domain: System.get_env("MAILGUN_DOMAIN")
  #
  # Most non-SMTP adapters require an API client. Swoosh supports Req, Hackney,
  # and Finch out-of-the-box. This configuration is typically done at
  # compile-time in your config/prod.exs:
  #
  #     config :swoosh, :api_client, Swoosh.ApiClient.Req
  #
  # See https://hexdocs.pm/swoosh/Swoosh.html#module-installation for details.
end
