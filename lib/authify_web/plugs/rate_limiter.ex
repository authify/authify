defmodule AuthifyWeb.Plugs.RateLimiter do
  @moduledoc """
  Rate limiting plugs using Hammer for different endpoint types.

  Provides configurable rate limiting for:
  - Authentication endpoints (login, password reset)
  - OAuth/OIDC endpoints (authorize, token)
  - SAML endpoints (SSO, SLO)
  - Management API endpoints

  Uses client IP address as the primary identifier, with optional
  user-based rate limiting for authenticated requests.

  ## Configuration

  Rate limits are configured per-plug and can be customized via
  application config or environment variables.

  ## Distributed Behavior

  When running in a cluster with Phoenix.PubSub configured, rate
  limit counters are eventually consistent across all nodes.
  """

  import Plug.Conn
  require Logger

  @behaviour Plug

  @doc """
  Initializes the plug with rate limiting options.
  """
  def init(opts), do: opts

  @doc """
  Performs rate limiting check based on the configured limiter type.
  """
  def call(conn, limiter_type) when is_atom(limiter_type) do
    apply(__MODULE__, limiter_type, [conn, []])
  end

  def call(conn, opts) when is_list(opts) do
    rate_limit(conn, opts)
  end

  @doc """
  Rate limits authentication endpoints.

  Reads configuration from organization settings.
  Default: 10 requests per minute per IP (if no config found)
  Scope: login, password_reset, signup
  """
  def auth_rate_limit(conn, opts \\ []) do
    {limit, scale_ms} = get_configured_limits(conn, :auth, opts, 10, 60_000)
    scope = Keyword.get(opts, :scope, "auth")

    check_rate(conn, "#{scope}:#{get_client_id(conn)}", scale_ms, limit)
  end

  @doc """
  Rate limits OAuth/OIDC endpoints.

  Reads configuration from organization settings.
  Default: 60 requests per minute per IP (if no config found)
  Higher limit for OAuth since apps may make multiple requests
  during the authorization flow.
  """
  def oauth_rate_limit(conn, opts \\ []) do
    {limit, scale_ms} = get_configured_limits(conn, :oauth, opts, 60, 60_000)
    scope = Keyword.get(opts, :scope, "oauth")

    check_rate(conn, "#{scope}:#{get_client_id(conn)}", scale_ms, limit)
  end

  @doc """
  Rate limits SAML endpoints.

  Reads configuration from organization settings.
  Default: 30 requests per minute per IP (if no config found)
  SAML flows are typically less frequent than OAuth.
  """
  def saml_rate_limit(conn, opts \\ []) do
    {limit, scale_ms} = get_configured_limits(conn, :saml, opts, 30, 60_000)
    scope = Keyword.get(opts, :scope, "saml")

    check_rate(conn, "#{scope}:#{get_client_id(conn)}", scale_ms, limit)
  end

  @doc """
  Rate limits Management API endpoints.

  Reads configuration from organization settings.
  Default: 100 requests per minute per IP or authenticated user (if no config found)
  Higher limit for API usage, with user-scoped limiting for authenticated requests.
  """
  def api_rate_limit(conn, opts \\ []) do
    {limit, scale_ms} = get_configured_limits(conn, :api, opts, 100, 60_000)
    scope = Keyword.get(opts, :scope, "api")

    # Use user ID if authenticated, otherwise fall back to IP
    identifier = get_user_id(conn) || get_client_id(conn)

    check_rate(conn, "#{scope}:#{identifier}", scale_ms, limit)
  end

  @doc """
  Rate limits SCIM 2.0 endpoints.

  Reads configuration from organization settings.
  Default: 100 requests per minute per IP (if no config found)
  SCIM is used for automated provisioning, similar rate to Management API.
  """
  def scim_rate_limit(conn, opts \\ []) do
    {limit, scale_ms} = get_configured_limits(conn, :scim, opts, 100, 60_000)
    scope = Keyword.get(opts, :scope, "scim")

    check_rate(conn, "#{scope}:#{get_client_id(conn)}", scale_ms, limit)
  end

  @doc """
  Generic rate limiter with custom parameters.

  Useful for specific endpoints that need different rate limits.
  """
  def rate_limit(conn, opts) do
    scale_ms = Keyword.fetch!(opts, :scale_ms)
    limit = Keyword.fetch!(opts, :limit)
    scope = Keyword.get(opts, :scope, "generic")

    check_rate(conn, "#{scope}:#{get_client_id(conn)}", scale_ms, limit)
  end

  # Private functions

  defp check_rate(conn, bucket_key, scale_ms, limit) do
    # Check if rate limiting is enabled (allows tests to disable it)
    if Application.get_env(:authify, :rate_limiting_enabled, true) do
      case Authify.RateLimit.hit(bucket_key, scale_ms, limit) do
        {:allow, _count} ->
          conn

        {:deny, retry_after} ->
          conn
          |> put_resp_header("retry-after", to_string(retry_after))
          |> send_rate_limit_response()
          |> halt()

        {:error, reason} ->
          # Log the error but don't block the request
          Logger.error("Rate limiting error for #{bucket_key}: #{inspect(reason)}")
          conn
      end
    else
      # Rate limiting disabled, allow all requests
      conn
    end
  end

  defp send_rate_limit_response(conn) do
    content_type = get_req_header(conn, "accept") |> List.first() || ""

    cond do
      String.contains?(content_type, "json") ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(429, Jason.encode!(%{error: "Rate limit exceeded. Please try again later."}))

      String.contains?(content_type, "html") or
          conn.request_path =~ ~r/^\/(login|password_reset|oauth|saml)/ ->
        conn
        |> put_resp_content_type("text/html")
        |> send_resp(429, """
        <!DOCTYPE html>
        <html>
        <head>
          <title>Rate Limit Exceeded</title>
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <style>
            body {
              font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
              max-width: 600px;
              margin: 100px auto;
              padding: 20px;
              text-align: center;
            }
            .error-code { font-size: 72px; color: #dc3545; font-weight: bold; }
            h1 { color: #333; }
            p { color: #666; line-height: 1.6; }
            .retry { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 20px; }
          </style>
        </head>
        <body>
          <div class="error-code">429</div>
          <h1>Too Many Requests</h1>
          <p>You've made too many requests in a short period of time.</p>
          <div class="retry">
            <strong>Please wait a moment and try again.</strong>
          </div>
        </body>
        </html>
        """)

      true ->
        conn
        |> put_resp_content_type("text/plain")
        |> send_resp(429, "Rate limit exceeded. Please try again later.")
    end
  end

  defp get_client_id(conn) do
    # Use the real client IP, accounting for proxies
    case get_req_header(conn, "x-forwarded-for") do
      [ip | _] ->
        # Take the first IP from X-Forwarded-For
        ip
        |> String.split(",")
        |> List.first()
        |> String.trim()

      [] ->
        # Fall back to remote_ip
        conn.remote_ip
        |> :inet.ntoa()
        |> to_string()
    end
  end

  defp get_user_id(conn) do
    # Try to get the authenticated user ID from Guardian
    case Authify.Guardian.Plug.current_resource(conn) do
      %{id: user_id} -> "user:#{user_id}"
      _ -> nil
    end
  end

  defp get_organization(conn) do
    # Try to get organization from conn assigns (set by organization context plug)
    case Map.get(conn.assigns, :current_organization) do
      nil ->
        # Fall back to user's organization if authenticated
        case Authify.Guardian.Plug.current_resource(conn) do
          %{organization: org} when not is_nil(org) ->
            org

          %{organization_id: org_id} when not is_nil(org_id) ->
            Authify.Accounts.get_organization!(org_id)

          _ ->
            nil
        end

      org ->
        org
    end
  end

  defp get_configured_limits(conn, scope, opts, default_limit, default_scale_ms) do
    # Allow opts to override (for testing or special cases)
    if Keyword.has_key?(opts, :limit) or Keyword.has_key?(opts, :scale_ms) do
      limit = Keyword.get(opts, :limit, default_limit)
      scale_ms = Keyword.get(opts, :scale_ms, default_scale_ms)
      {limit, scale_ms}
    else
      # Get from organization configuration
      case get_organization(conn) do
        nil ->
          # No organization context, use defaults
          {default_limit, default_scale_ms}

        org ->
          # Use configured limits
          Authify.RateLimit.Config.get_limit(org, scope)
      end
    end
  end
end
