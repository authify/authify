defmodule AuthifyWeb.Helpers.ConnHelpers do
  @moduledoc """
  Helper functions for extracting information from Plug.Conn structs.
  """

  @doc """
  Extracts the client IP address from the connection.

  Checks the X-Forwarded-For header first (for proxy/load balancer scenarios),
  then falls back to the direct remote_ip.
  """
  def get_client_ip(conn) do
    case Plug.Conn.get_req_header(conn, "x-forwarded-for") do
      [ip | _] -> ip
      [] -> to_string(:inet_parse.ntoa(conn.remote_ip))
    end
  end

  @doc """
  Extracts the user agent from the connection.

  Returns "Unknown" if no user agent header is present.
  """
  def get_user_agent(conn) do
    case Plug.Conn.get_req_header(conn, "user-agent") do
      [user_agent | _] -> user_agent
      [] -> "Unknown"
    end
  end
end
