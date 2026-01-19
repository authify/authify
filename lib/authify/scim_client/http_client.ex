defmodule Authify.SCIMClient.HTTPClient do
  @moduledoc """
  HTTP client for outbound SCIM 2.0 requests using Req.
  Handles authentication, error handling, and logging.
  """

  @scim_content_type "application/scim+json"

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

  # Private functions

  defp request(scim_client, method, path, body) do
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

    case Req.request(opts) do
      {:ok, %{status: status} = response} when status in 200..299 ->
        {:ok, response.body, status}

      {:ok, %{status: status} = response} ->
        {:error, {:http_error, status, response.body}}

      {:error, reason} ->
        {:error, {:network_error, reason}}
    end
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
end
