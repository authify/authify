defmodule AuthifyWeb.Auth.ReturnTo do
  @moduledoc """
  Validates and tracks post-authentication "return to" destinations.

  The login flow accepts a `return_to` value (from the OAuth authorize and
  SAML SSO entry points) and, after successful authentication, sends the user
  back to that destination. Because the login endpoints are unauthenticated
  and the value can originate from caller-controlled query parameters, only
  **same-origin, absolute-path** values are ever honored.

  Validation is delegated to the standard library's structural URI parser
  (`URI.new/1`), augmented with a check of the percent-decoded value. Browsers
  decode and strip characters from a `Location` header before resolving it, so
  a value must remain a rooted local path in both its raw and decoded forms.
  This defeats protocol-relative tricks such as `//evil.com` and encoded
  variants such as `/%2F%2Fevil.com` or `/%09/evil.com`.

  Accepted values must:

    * be a non-empty, valid UTF-8 binary of at most 1024 bytes
    * parse to a URI with no scheme and no host
    * have a rooted absolute path (starting with `/`, but not `//`)
    * remain rooted, unbackslashed, and control-character-free after decoding

  Anything else is rejected, so a stored value is always safe to hand to
  `Phoenix.Controller.redirect(to: ...)`. Validation never raises, and the
  length bound keeps the stored session cookie well under Plug's 4096-byte
  limit.
  """

  import Plug.Conn

  @session_key :return_to

  # Generous upper bound for a real path; also protects the session cookie
  # from overflow (Plug raises when a signed cookie exceeds 4096 bytes).
  @max_length 1024

  @doc """
  Validates and stores a `return_to` value for the current session.

  Unsafe or missing values clear any previously stored destination rather
  than being persisted.
  """
  def store(conn, value) do
    case safe_local_path(value) do
      {:ok, path} -> put_session(conn, @session_key, path)
      :error -> delete_session(conn, @session_key)
    end
  end

  @doc """
  Returns the stored `return_to` path without clearing it.

  The stored value is re-validated on read, so a session value that was not
  written by `store/2` (or no longer passes validation) is treated as absent.
  """
  def peek(conn) do
    case get_session(conn, @session_key) do
      path when is_binary(path) ->
        if match?({:ok, _}, safe_local_path(path)), do: path, else: nil

      _ ->
        nil
    end
  end

  @doc """
  Returns the stored `return_to` path and a connection with it cleared.

  The value is used at most once; subsequent logins fall back to the default
  destination.
  """
  def consume(conn) do
    path = peek(conn)
    {delete_session(conn, @session_key), path}
  end

  @doc """
  Returns `{conn, destination}` where `destination` is the stored `return_to`
  path if present, otherwise `default`.

  The stored value is cleared so it is only honored once.
  """
  def destination(conn, default) do
    {conn, path} = consume(conn)
    {conn, path || default}
  end

  @doc """
  Returns a safe same-origin absolute path for the given value.

  Returns `{:ok, path}` or `:error`. Never raises, even for malformed or
  invalid-UTF-8 input.
  """
  def safe_local_path(value) when is_binary(value) and value != "" do
    with true <- String.valid?(value),
         true <- byte_size(value) <= @max_length,
         :ok <- validate_raw(value),
         {:ok, decoded} <- decode(value),
         true <- String.valid?(decoded),
         :ok <- validate_decoded(decoded) do
      {:ok, value}
    else
      _ -> :error
    end
  end

  def safe_local_path(_value), do: :error

  defp decode(value) do
    {:ok, URI.decode(value)}
  rescue
    ArgumentError -> :error
  end

  # Structural validation via the stdlib parser: no scheme, no host, and a
  # rooted path that is not protocol-relative. `URI.new/1` also rejects
  # control characters and backslashes.
  defp validate_raw(value) do
    case URI.new(value) do
      {:ok, %URI{scheme: nil, host: nil, path: path}} when is_binary(path) ->
        if String.starts_with?(path, "/") and not String.starts_with?(path, "//"),
          do: :ok,
          else: :error

      _ ->
        :error
    end
  rescue
    # `URI.new/1` can raise (e.g. FunctionClauseError) on some malformed input.
    _ -> :error
  end

  # Re-check the decoded value for tricks that only appear after decoding.
  defp validate_decoded(value) do
    cond do
      not String.starts_with?(value, "/") -> :error
      String.starts_with?(value, "//") -> :error
      String.contains?(value, "\\") -> :error
      control_char?(value) -> :error
      true -> :ok
    end
  end

  defp control_char?(value) do
    value
    |> :binary.bin_to_list()
    |> Enum.any?(fn byte -> byte < 0x20 or byte == 0x7F end)
  end
end
