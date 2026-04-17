defmodule AuthifyTest.OAuthClient do
  @moduledoc false

  @endpoint AuthifyWeb.Endpoint

  import Plug.Conn, only: [get_resp_header: 2, put_req_header: 3]
  import Phoenix.ConnTest
  import AuthifyWeb.ConnCase, only: [log_in_user: 2]

  defstruct [:conn, :app, :org]

  def new(conn, app, org), do: %__MODULE__{conn: conn, app: app, org: org}

  def generate_pkce do
    verifier = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
    challenge = Base.url_encode64(:crypto.hash(:sha256, verifier), padding: false)
    {verifier, challenge}
  end

  # Placeholder to suppress unused-import warnings until subsequent tasks
  # implement HTTP helpers that use these imports.
  @doc false
  def __imports_used__ do
    conn = build_conn()
    conn = put_req_header(conn, "accept", "application/json")
    _headers = get_resp_header(conn, "location")
    _client = log_in_user(conn, %{})
    @endpoint
  end
end
