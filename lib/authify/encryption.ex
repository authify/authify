defmodule Authify.Encryption do
  @moduledoc """
  Provides encryption and decryption utilities for sensitive fields.

  Uses AES-256-GCM encryption with PBKDF2 key derivation for secure storage
  of sensitive data like private keys, tokens, and credentials.
  """

  @doc """
  Encrypts a value for secure storage using the configured encryption password.

  ## Examples

      iex> Authify.Encryption.encrypt("sensitive_data")
      "base64_encoded_encrypted_data..."

  """
  def encrypt(value) when is_binary(value) do
    password = get_encryption_password()
    encrypt_with_password(value, password)
  end

  @doc """
  Decrypts a previously encrypted value.

  ## Examples

      iex> Authify.Encryption.decrypt(encrypted_value)
      {:ok, "sensitive_data"}

  """
  def decrypt(encrypted_value) when is_binary(encrypted_value) do
    password = get_encryption_password()
    decrypt_with_password(encrypted_value, password)
  end

  @doc """
  Encrypts a value with a specific password.

  Useful for scenarios where you want to use a different password than the default.
  """
  def encrypt_with_password(value, password)
      when is_binary(value) and is_binary(password) do
    try do
      # Generate a random salt
      salt = :crypto.strong_rand_bytes(16)

      # Derive key from password using PBKDF2
      key = derive_key(password, salt, 100_000, 32)

      # Generate a random IV
      iv = :crypto.strong_rand_bytes(16)

      # Encrypt the value using AES-256-GCM
      {ciphertext, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, value, "", true)

      # Combine salt, iv, tag, and ciphertext
      encrypted_data = salt <> iv <> tag <> ciphertext

      # Encode as Base64 for storage
      Base.encode64(encrypted_data)
    rescue
      error ->
        {:error, "Failed to encrypt value: #{inspect(error)}"}
    end
  end

  @doc """
  Decrypts a value with a specific password.

  Returns `{:ok, decrypted_value}` on success or `{:error, reason}` on failure.
  """
  def decrypt_with_password(encrypted_value, password)
      when is_binary(encrypted_value) and is_binary(password) do
    try do
      # Decode from Base64
      encrypted_data = Base.decode64!(encrypted_value)

      # Extract components
      <<salt::binary-size(16), iv::binary-size(16), tag::binary-size(16), ciphertext::binary>> =
        encrypted_data

      # Derive key from password using same parameters
      key = derive_key(password, salt, 100_000, 32)

      # Decrypt using AES-256-GCM
      case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, "", tag, false) do
        value when is_binary(value) ->
          {:ok, value}

        :error ->
          {:error, "Failed to decrypt value - invalid password or corrupted data"}
      end
    rescue
      error ->
        {:error, "Failed to decrypt value: #{inspect(error)}"}
    end
  end

  # Private helper functions

  defp get_encryption_password do
    Application.get_env(:authify, :encryption_password) ||
      raise """
      Encryption password not configured!
      Set ENCRYPTION_PASSWORD environment variable or configure :encryption_password
      """
  end

  defp derive_key(password, salt, iterations, key_length) do
    :crypto.pbkdf2_hmac(:sha256, password, salt, iterations, key_length)
  end
end
