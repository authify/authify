defmodule Authify.Security.Sanitizer do
  @moduledoc """
  Provides functions to sanitize sensitive data from strings before displaying
  them in user interfaces, logs, or error messages.

  This module helps prevent accidental exposure of sensitive information like
  passwords, tokens, secrets, and other credentials that might appear in
  error messages, debug output, or stack traces.

  ## Usage

      iex> error_message = "hashed_password: \\"$2b$12$abc123...\\""
      iex> Authify.Security.Sanitizer.sanitize(error_message)
      "hashed_password: \\"[REDACTED]\\""

  ## Sensitive Fields

  The following types of sensitive data are automatically redacted:

  - **Passwords**: `hashed_password`, `password`, `password_confirmation`
  - **Secrets**: `totp_secret`, `secret_key`, `api_key`, `encryption_key`, `client_secret`
  - **Tokens**: `password_reset_token`, `verification_token`, `access_token`, `refresh_token`
  - **Backup Codes**: `totp_backup_codes` (shows count instead of values)
  """

  @doc """
  Sanitizes sensitive data from the given content.

  Returns the content with sensitive fields replaced by "[REDACTED]" markers.
  Non-string content is returned unchanged.

  ## Examples

      iex> Authify.Security.Sanitizer.sanitize(nil)
      nil

      iex> Authify.Security.Sanitizer.sanitize("")
      ""

      iex> Authify.Security.Sanitizer.sanitize("normal text")
      "normal text"

      iex> Authify.Security.Sanitizer.sanitize("totp_secret: \\"abc123\\"")
      "totp_secret: \\"[REDACTED]\\""
  """
  def sanitize(nil), do: nil
  def sanitize(""), do: ""

  def sanitize(content) when is_binary(content) do
    content
    |> sanitize_passwords()
    |> sanitize_secrets()
    |> sanitize_tokens()
    |> sanitize_backup_codes()
  end

  def sanitize(content), do: content

  @doc """
  Sanitizes a map by converting it to JSON, sanitizing, and parsing back.
  Useful for sanitizing error data structures before display.

  ## Examples

      iex> Authify.Security.Sanitizer.sanitize_map(%{password: "secret"})
      # Returns map with password redacted in string representation
  """
  def sanitize_map(map) when is_map(map) do
    case Jason.encode(map) do
      {:ok, json} ->
        sanitized_json = sanitize(json)

        case Jason.decode(sanitized_json) do
          {:ok, sanitized_map} -> sanitized_map
          {:error, _} -> map
        end

      {:error, _} ->
        map
    end
  end

  def sanitize_map(content), do: content

  # Private sanitization functions

  # Redact password fields (handles both regular and JSON-escaped quotes)
  defp sanitize_passwords(content) do
    content
    # JSON-escaped quotes
    |> String.replace(
      ~r/hashed_password:\s*\\"[^\\"]+\\"/i,
      ~s(hashed_password: \\"[REDACTED]\\")
    )
    |> String.replace(~r/password:\s*\\"[^\\"]+\\"/i, ~s(password: \\"[REDACTED]\\"))
    |> String.replace(
      ~r/password_confirmation:\s*\\"[^\\"]+\\"/i,
      ~s(password_confirmation: \\"[REDACTED]\\")
    )
    # Regular quotes
    |> String.replace(~r/hashed_password:\s*"[^"]+"/i, ~s(hashed_password: "[REDACTED]"))
    |> String.replace(~r/password:\s*"[^"]+"/i, ~s(password: "[REDACTED]"))
    |> String.replace(
      ~r/password_confirmation:\s*"[^"]+"/i,
      ~s(password_confirmation: "[REDACTED]")
    )
  end

  # Redact secret fields (TOTP, API keys, encryption keys, etc.)
  defp sanitize_secrets(content) do
    content
    # JSON-escaped quotes
    |> String.replace(~r/totp_secret:\s*\\"[^\\"]+\\"/i, ~s(totp_secret: \\"[REDACTED]\\"))
    |> String.replace(~r/secret_key:\s*\\"[^\\"]+\\"/i, ~s(secret_key: \\"[REDACTED]\\"))
    |> String.replace(~r/api_key:\s*\\"[^\\"]+\\"/i, ~s(api_key: \\"[REDACTED]\\"))
    |> String.replace(~r/encryption_key:\s*\\"[^\\"]+\\"/i, ~s(encryption_key: \\"[REDACTED]\\"))
    |> String.replace(~r/client_secret:\s*\\"[^\\"]+\\"/i, ~s(client_secret: \\"[REDACTED]\\"))
    |> String.replace(~r/private_key:\s*\\"[^\\"]+\\"/i, ~s(private_key: \\"[REDACTED]\\"))
    # Regular quotes
    |> String.replace(~r/totp_secret:\s*"[^"]+"/i, ~s(totp_secret: "[REDACTED]"))
    |> String.replace(~r/secret_key:\s*"[^"]+"/i, ~s(secret_key: "[REDACTED]"))
    |> String.replace(~r/api_key:\s*"[^"]+"/i, ~s(api_key: "[REDACTED]"))
    |> String.replace(~r/encryption_key:\s*"[^"]+"/i, ~s(encryption_key: "[REDACTED]"))
    |> String.replace(~r/client_secret:\s*"[^"]+"/i, ~s(client_secret: "[REDACTED]"))
    |> String.replace(~r/private_key:\s*"[^"]+"/i, ~s(private_key: "[REDACTED]"))
  end

  # Redact token fields (reset tokens, verification tokens, OAuth tokens, etc.)
  defp sanitize_tokens(content) do
    content
    # JSON-escaped quotes
    |> String.replace(
      ~r/password_reset_token:\s*\\"[^\\"]+\\"/i,
      ~s(password_reset_token: \\"[REDACTED]\\")
    )
    |> String.replace(
      ~r/plaintext_reset_token:\s*\\"[^\\"]+\\"/i,
      ~s(plaintext_reset_token: \\"[REDACTED]\\")
    )
    |> String.replace(
      ~r/verification_token:\s*\\"[^\\"]+\\"/i,
      ~s(verification_token: \\"[REDACTED]\\")
    )
    |> String.replace(~r/access_token:\s*\\"[^\\"]+\\"/i, ~s(access_token: \\"[REDACTED]\\"))
    |> String.replace(~r/refresh_token:\s*\\"[^\\"]+\\"/i, ~s(refresh_token: \\"[REDACTED]\\"))
    |> String.replace(~r/bearer_token:\s*\\"[^\\"]+\\"/i, ~s(bearer_token: \\"[REDACTED]\\"))
    # Regular quotes
    |> String.replace(
      ~r/password_reset_token:\s*"[^"]+"/i,
      ~s(password_reset_token: "[REDACTED]")
    )
    |> String.replace(
      ~r/plaintext_reset_token:\s*"[^"]+"/i,
      ~s(plaintext_reset_token: "[REDACTED]")
    )
    |> String.replace(~r/verification_token:\s*"[^"]+"/i, ~s(verification_token: "[REDACTED]"))
    |> String.replace(~r/access_token:\s*"[^"]+"/i, ~s(access_token: "[REDACTED]"))
    |> String.replace(~r/refresh_token:\s*"[^"]+"/i, ~s(refresh_token: "[REDACTED]"))
    |> String.replace(~r/bearer_token:\s*"[^"]+"/i, ~s(bearer_token: "[REDACTED]"))
  end

  # Redact backup codes (shows count instead of actual codes)
  defp sanitize_backup_codes(content) do
    content
    # JSON-escaped quotes with escaped backslashes in the array
    |> then(fn text ->
      Regex.replace(
        ~r/totp_backup_codes:\s*\\"(\[.*?\])\\"/s,
        text,
        fn full_match, codes ->
          count = Regex.scan(~r/\$2b\$/, codes) |> length()
          String.replace(full_match, codes, "[REDACTED - #{count} codes]")
        end
      )
    end)
    # Regular quotes
    |> then(fn text ->
      Regex.replace(
        ~r/totp_backup_codes:\s*"(\[.*?\])"/s,
        text,
        fn full_match, codes ->
          count = Regex.scan(~r/\$2b\$/, codes) |> length()
          String.replace(full_match, codes, "[REDACTED - #{count} codes]")
        end
      )
    end)
  end
end
