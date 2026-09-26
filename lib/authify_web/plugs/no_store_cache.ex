defmodule AuthifyWeb.Plugs.NoStoreCache do
  @moduledoc """
  Marks a response as non-cacheable with `Cache-Control: no-store`.

  Authify's default response header is `max-age=0, private, must-revalidate`.
  The `private` directive prevents shared caches (reverse proxies and CDNs)
  from storing a response, but it still allows the *browser's* own private
  cache to write the body to disk. For responses carrying tokens, credentials,
  or personal data that is too weak.

  `no-store` forbids storing the response in any cache. This plug is applied
  to the sensitive endpoints where that matters:

    * OAuth 2.0 token and userinfo endpoints (RFC 6749 Section 5.1 requires
      `Cache-Control: no-store` on responses containing tokens)
    * Management API endpoints (API responses may include secrets, signing
      keys, and user personal data)
    * SCIM 2.0 endpoints (provisioned user data)
    * MFA verification screens (pending authentication state)

  A matching `Pragma: no-cache` header is included for HTTP/1.0 intermediaries,
  as recommended by RFC 6749 Section 5.1.
  """

  import Plug.Conn

  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    conn
    |> put_resp_header("cache-control", "no-store")
    |> put_resp_header("pragma", "no-cache")
  end
end
