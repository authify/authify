defmodule Authify.SCIMClient.HTTPClient do
  @moduledoc """
  HTTP client for outbound SCIM 2.0 requests using Req.
  Handles authentication, error handling, logging, telemetry, and rate limiting.
  """

  require Logger

  alias Authify.Accounts.Organization
  alias Authify.Configurations

  @scim_content_type "application/scim+json"
  @default_request_delay_ms 100

  @doc """
  Creates a user in the remote SCIM provider.
  """
  def create_user(scim_client, user_payload) do
    request(scim_client, :post, "/Users", user_payload)
  end

  @doc """
  Updates a user in the remote SCIM provider.
  """
  def update_user(scim_client, external_id, user_payload) do
    request(scim_client, :put, "/Users/#{external_id}", user_payload)
  end

  @doc """
  Deletes a user from the remote SCIM provider.
  """
  def delete_user(scim_client, external_id) do
    request(scim_client, :delete, "/Users/#{external_id}", nil)
  end

  @doc """
  Creates a group in the remote SCIM provider.
  """
  def create_group(scim_client, group_payload) do
    request(scim_client, :post, "/Groups", group_payload)
  end

  @doc """
  Updates a group in the remote SCIM provider.
  """
  def update_group(scim_client, external_id, group_payload) do
    request(scim_client, :put, "/Groups/#{external_id}", group_payload)
  end

  @doc """
  Deletes a group from the remote SCIM provider.
  """
  def delete_group(scim_client, external_id) do
    request(scim_client, :delete, "/Groups/#{external_id}", nil)
  end

  @doc """
  Tests the connection to a SCIM provider by fetching the ServiceProviderConfig.
  This is a read-only operation that validates authentication and connectivity.
  """
  def test_connection(scim_client) do
    case request(scim_client, :get, "/ServiceProviderConfig", nil) do
      {:ok, _body, status} ->
        {:ok, "Connection successful (HTTP #{status})"}

      {:error, {:http_error, status, body}} ->
        error_msg = extract_error_message(body)
        {:error, "HTTP #{status}: #{error_msg}"}

      {:error, {:network_error, reason}} ->
        {:error, "Network error: #{format_network_error(reason)}"}
    end
  end

  # Private functions

  defp request(scim_client, method, path, body) do
    # Apply rate limiting to prevent overwhelming downstream systems
    apply_rate_limit(scim_client)

    url = build_url(scim_client.base_url, path)
    headers = build_headers(scim_client)

    opts =
      [
        method: method,
        url: url,
        headers: headers,
        retry: false,
        receive_timeout: 30_000
      ]
      |> maybe_add_json_body(body)

    metadata = %{
      scim_client_id: scim_client.id,
      method: method,
      path: path,
      url: url
    }

    start_time = System.monotonic_time()

    result =
      case Req.request(opts) do
        {:ok, %{status: status} = response} when status in 200..299 ->
          Logger.debug("SCIM request successful: #{method} #{path} -> #{status}")
          {:ok, response.body, status}

        {:ok, %{status: status} = response} ->
          error_msg = extract_error_message(response.body)

          Logger.warning("SCIM request failed: #{method} #{path} -> #{status}: #{error_msg}")

          {:error, {:http_error, status, response.body}}

        {:error, reason} ->
          Logger.error("SCIM network error: #{method} #{path} -> #{inspect(reason)}")
          {:error, {:network_error, reason}}
      end

    duration = System.monotonic_time() - start_time

    # Emit telemetry event
    :telemetry.execute(
      [:authify, :scim_client, :http_request],
      %{duration: duration},
      Map.put(metadata, :result, elem(result, 0))
    )

    result
  end

  defp maybe_add_json_body(opts, nil), do: opts
  defp maybe_add_json_body(opts, body), do: Keyword.put(opts, :json, body)

  defp build_headers(scim_client) do
    base_headers = [
      {"Content-Type", @scim_content_type},
      {"Accept", @scim_content_type}
    ]

    auth_header = build_auth_header(scim_client)
    [auth_header | base_headers]
  end

  defp build_auth_header(%{auth_type: "bearer", auth_credential: token}) do
    {"Authorization", "Bearer #{token}"}
  end

  defp build_auth_header(%{auth_type: "basic", auth_username: user, auth_credential: pass}) do
    credentials = Base.encode64("#{user}:#{pass}")
    {"Authorization", "Basic #{credentials}"}
  end

  defp build_url(base_url, path) do
    base_url
    |> String.trim_trailing("/")
    |> Kernel.<>(path)
  end

  # Extract error message from SCIM error response
  defp extract_error_message(body) when is_map(body) do
    cond do
      Map.has_key?(body, "detail") -> body["detail"]
      Map.has_key?(body, "error") -> body["error"]
      Map.has_key?(body, "message") -> body["message"]
      true -> inspect(body)
    end
  end

  defp extract_error_message(body) when is_binary(body), do: body
  defp extract_error_message(body), do: inspect(body)

  # Format network error for better readability
  defp format_network_error(%{__exception__: true, message: message}) when is_binary(message) do
    message
  end

  defp format_network_error(%{__exception__: true} = exception) do
    Exception.message(exception)
  end

  # Rate limiting implementation using ETS table
  defp apply_rate_limit(scim_client) do
    table_name = :scim_client_rate_limiter

    # Ensure ETS table exists
    unless :ets.whereis(table_name) != :undefined do
      :ets.new(table_name, [:named_table, :public, :set])
    end

    current_time = System.monotonic_time(:millisecond)
    delay_ms = get_request_delay(scim_client)

    case :ets.lookup(table_name, scim_client.id) do
      [{_, last_request_time}] ->
        elapsed = current_time - last_request_time

        if elapsed < delay_ms do
          # Need to wait before making next request
          sleep_time = delay_ms - elapsed
          Process.sleep(sleep_time)
        end

      [] ->
        # First request for this client, no delay needed
        :ok
    end

    # Update last request time
    :ets.insert(table_name, {scim_client.id, System.monotonic_time(:millisecond)})
  end

  # Get the configured request delay for this SCIM client's organization
  defp get_request_delay(scim_client) do
    organization = Authify.Repo.get!(Organization, scim_client.organization_id)

    delay =
      Configurations.get_organization_setting(
        organization,
        :scim_client_request_delay_ms
      )

    # Use configured delay or fall back to default
    delay || @default_request_delay_ms
  end
end
