# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :authify,
  ecto_repos: [Authify.Repo],
  generators: [timestamp_type: :utc_datetime]

# Configures the endpoint
config :authify, AuthifyWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [html: AuthifyWeb.ErrorHTML, json: AuthifyWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: Authify.PubSub,
  live_view: [signing_salt: "H9twhOz4"]

# Configures the mailer
#
# By default it uses the "Local" adapter which stores the emails
# locally. You can see the emails in your browser, at "/dev/mailbox".
#
# For production it's recommended to configure a different adapter
# at the `config/runtime.exs`.
config :authify, Authify.Mailer, adapter: Swoosh.Adapters.Local

# Configure esbuild (the version is required)
config :esbuild,
  version: "0.25.4",
  authify: [
    args:
      ~w(js/app.js --bundle --target=es2022 --outdir=../priv/static/assets --external:/fonts/* --external:/images/* --loader:.woff=file --loader:.woff2=file --alias:@=.),
    cd: Path.expand("../assets", __DIR__),
    env: %{"NODE_PATH" => [Path.expand("../deps", __DIR__), Mix.Project.build_path()]}
  ]

# Configures Elixir's Logger
config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Guardian configuration
config :authify, Authify.Guardian,
  issuer: "authify",
  secret_key:
    System.get_env("GUARDIAN_SECRET_KEY") ||
      System.get_env("SECRET_KEY_BASE") ||
      "your-secret-key-here-please-change-in-production"

# Hammer rate limiting configuration
config :hammer,
  backend: {
    Hammer.Backend.ETS,
    [
      expiry_ms: 60_000 * 60 * 4,
      cleanup_interval_ms: 60_000 * 10
    ]
  }

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
