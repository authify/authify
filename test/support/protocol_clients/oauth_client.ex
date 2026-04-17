defmodule AuthifyTest.OAuthClient do
  @moduledoc false

  defstruct [:conn, :app, :org]

  def new(conn, app, org), do: %__MODULE__{conn: conn, app: app, org: org}

  def generate_pkce do
    verifier = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
    challenge = Base.url_encode64(:crypto.hash(:sha256, verifier), padding: false)
    {verifier, challenge}
  end
end
