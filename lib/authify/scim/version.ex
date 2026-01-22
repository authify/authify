defmodule Authify.SCIM.Version do
  @moduledoc """
  Generates and validates SCIM resource versions (ETags) per RFC 7644 Section 3.14.

  Uses weak ETags with the format: `W/"<id>-<unix_timestamp>-<phash2_hex>"`

  The version is based on:
  - Resource ID
  - Last modified timestamp (scim_updated_at or updated_at)
  - Fast phash2 hash for collision resistance

  ## Examples

      iex> user = %{id: 123, scim_updated_at: ~U[2024-01-18 12:00:00Z]}
      iex> version = Authify.SCIM.Version.generate_version(user)
      iex> version
      "123-1705579200-a1b2c3d4"

      iex> etag = Authify.SCIM.Version.generate_etag(user)
      iex> etag
      ~s(W/"123-1705579200-a1b2c3d4")

      iex> Authify.SCIM.Version.parse_etag(~s(W/"123-1705579200-a1b2c3d4"))
      "123-1705579200-a1b2c3d4"
  """

  @doc """
  Generates a version string for a SCIM resource.

  Returns the plain version string without the W/ prefix, suitable for
  the `meta.version` field in SCIM responses.

  ## Parameters

  - `resource` - A struct with `id` and either `scim_updated_at` or `updated_at`

  ## Returns

  A string in the format: `"<id>-<unix_timestamp>-<phash2_hex>"`
  """
  def generate_version(resource) do
    timestamp = get_timestamp(resource)
    unix_time = timestamp_to_unix(timestamp)
    hash = :erlang.phash2({resource.id, unix_time})
    hash_hex = Integer.to_string(hash, 16) |> String.downcase()

    "#{resource.id}-#{unix_time}-#{hash_hex}"
  end

  @doc """
  Generates a weak ETag header value for a SCIM resource.

  Returns the full ETag header value with the W/ prefix, suitable for
  HTTP ETag response headers.

  ## Parameters

  - `resource` - A struct with `id` and either `scim_updated_at` or `updated_at`

  ## Returns

  A string in the format: `W/"<id>-<unix_timestamp>-<phash2_hex>"`
  """
  def generate_etag(resource) do
    version = generate_version(resource)
    ~s(W/"#{version}")
  end

  @doc """
  Parses an ETag header value and extracts the version string.

  Handles both weak (W/) and strong ETags, stripping quotes and prefixes.

  ## Parameters

  - `etag_header` - The ETag header value (e.g., `W/"123-1705579200-a1b2c3d4"`)

  ## Returns

  The version string without quotes or W/ prefix, or `nil` if invalid.

  ## Examples

      iex> Authify.SCIM.Version.parse_etag(~s(W/"123-1705579200-a1b2c3d4"))
      "123-1705579200-a1b2c3d4"

      iex> Authify.SCIM.Version.parse_etag(~s("123-1705579200-a1b2c3d4"))
      "123-1705579200-a1b2c3d4"

      iex> Authify.SCIM.Version.parse_etag("invalid")
      nil
  """
  def parse_etag(nil), do: nil
  def parse_etag(""), do: nil

  def parse_etag(etag_header) when is_binary(etag_header) do
    etag_header
    |> String.trim()
    |> String.replace_prefix("W/", "")
    |> String.trim()
    |> case do
      "\"" <> rest ->
        rest
        |> String.trim_trailing("\"")
        |> validate_version_format()

      _ ->
        nil
    end
  end

  def parse_etag(_), do: nil

  # Private functions

  defp get_timestamp(resource) do
    cond do
      Map.has_key?(resource, :scim_updated_at) && resource.scim_updated_at ->
        resource.scim_updated_at

      Map.has_key?(resource, :updated_at) && resource.updated_at ->
        resource.updated_at

      true ->
        DateTime.utc_now()
    end
  end

  defp timestamp_to_unix(%DateTime{} = dt) do
    DateTime.to_unix(dt)
  end

  defp timestamp_to_unix(%NaiveDateTime{} = ndt) do
    ndt
    |> DateTime.from_naive!("Etc/UTC")
    |> DateTime.to_unix()
  end

  defp validate_version_format(version) do
    case String.split(version, "-") do
      [_id, _timestamp, _hash] -> version
      _ -> nil
    end
  end
end
