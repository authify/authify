import Config

# Set the runtime environment (used instead of Mix.env() which isn't available in releases)
config :authify, env: :test

# Configure your database
#
# The MIX_TEST_PARTITION environment variable can be used
# to provide built-in test partitioning in CI environment.
# Run `mix help test` for more information.
if System.get_env("CI_MODE") do
  config :authify, Authify.Repo,
    username: "authifytest",
    password: "authifytest",
    hostname: "127.0.0.1",
    database: "authify_test#{System.get_env("MIX_TEST_PARTITION")}",
    pool: Ecto.Adapters.SQL.Sandbox,
    pool_size: System.schedulers_online() * 2
else
  config :authify, Authify.Repo,
    username: "root",
    password: "",
    hostname: "localhost",
    database: "authify_test#{System.get_env("MIX_TEST_PARTITION")}",
    pool: Ecto.Adapters.SQL.Sandbox,
    pool_size: System.schedulers_online() * 2
end

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :authify, AuthifyWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "t2I8RWPriihUV+lAkspYyw9DBXXMXI0EBln95SrqepUXGlrrswafwLL2mw28xFPO",
  server: false

# In test we don't send emails
config :authify, Authify.Mailer, adapter: Swoosh.Adapters.Test

# Disable swoosh api client as it is only required for production adapters
config :swoosh, :api_client, false

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Enable helpful, but potentially expensive runtime checks
config :phoenix_live_view,
  enable_expensive_runtime_checks: true

# Disable rate limiting by default in tests
# Individual tests can enable it using the RateLimitTest helper module
config :authify, :rate_limiting_enabled, false

# Disable metrics in test environment
config :authify, :metrics_enabled, false
