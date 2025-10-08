defmodule AuthifyWeb.Plugs.ApiVersionNegotiation do
  @moduledoc """
  Plug for handling API version negotiation through Accept headers.

  Supports header-based versioning with formats like:
  - Accept: application/vnd.authify.v1+json
  - Accept: application/json (defaults to latest version)
  """

  import Plug.Conn

  @supported_versions ["v1"]
  @default_version "v1"
  @vendor_type "application/vnd.authify"

  def init(opts), do: opts

  def call(conn, _opts) do
    version = extract_api_version(conn)

    conn
    |> assign(:api_version, version)
    |> put_resp_header("x-api-version", version)
  end

  defp extract_api_version(conn) do
    accept_header = get_req_header(conn, "accept") |> List.first("")

    case parse_vendor_type(accept_header) do
      {:ok, version} when version in @supported_versions -> version
      {:ok, _unsupported} -> @default_version
      :error -> @default_version
    end
  end

  defp parse_vendor_type(accept_header) do
    cond do
      String.contains?(accept_header, @vendor_type) ->
        # Parse application/vnd.authify.v1+json
        case Regex.run(~r/#{@vendor_type}\.(\w+)\+json/, accept_header) do
          [_, version] -> {:ok, version}
          _ -> :error
        end

      String.contains?(accept_header, "application/json") ->
        {:ok, @default_version}

      true ->
        :error
    end
  end
end
