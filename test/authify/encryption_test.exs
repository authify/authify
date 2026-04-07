defmodule Authify.EncryptionTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Authify.Encryption

  describe "encrypt_with_password/2 and decrypt_with_password/2" do
    test "roundtrip: decrypting an encrypted value returns the original" do
      password = "test_password_123"
      plaintext = "sensitive data to protect"

      encrypted = Encryption.encrypt_with_password(plaintext, password)
      assert is_binary(encrypted)
      assert {:ok, ^plaintext} = Encryption.decrypt_with_password(encrypted, password)
    end

    test "encrypts empty string" do
      password = "test_password"
      encrypted = Encryption.encrypt_with_password("", password)
      assert is_binary(encrypted)
      assert {:ok, ""} = Encryption.decrypt_with_password(encrypted, password)
    end

    test "encrypts binary data with special characters" do
      password = "test_password"
      plaintext = "data with special chars: \n\t\0 unicode: 日本語"
      encrypted = Encryption.encrypt_with_password(plaintext, password)
      assert {:ok, ^plaintext} = Encryption.decrypt_with_password(encrypted, password)
    end

    test "produces different ciphertext for the same plaintext each time (random IV/salt)" do
      password = "test_password"
      plaintext = "same plaintext"
      encrypted1 = Encryption.encrypt_with_password(plaintext, password)
      encrypted2 = Encryption.encrypt_with_password(plaintext, password)
      refute encrypted1 == encrypted2
    end

    test "encrypted output is base64-encoded" do
      encrypted = Encryption.encrypt_with_password("test", "password")
      assert String.match?(encrypted, ~r/^[A-Za-z0-9+\/]+=*$/)
    end

    test "decryption with wrong password returns an error" do
      encrypted = Encryption.encrypt_with_password("secret", "correct_password")
      assert {:error, _reason} = Encryption.decrypt_with_password(encrypted, "wrong_password")
    end

    test "decryption of corrupted data returns an error" do
      password = "test_password"
      encrypted = Encryption.encrypt_with_password("secret", password)

      # Corrupt one byte in the ciphertext portion (after 48-byte salt+iv+tag prefix)
      corrupted =
        encrypted
        |> Base.decode64!()
        |> then(fn <<prefix::binary-size(48), byte::size(8), rest::binary>> ->
          <<prefix::binary, rem(byte + 1, 256)::size(8), rest::binary>>
        end)
        |> Base.encode64()

      assert {:error, _reason} = Encryption.decrypt_with_password(corrupted, password)
    end
  end

  describe "encrypt/1 and decrypt/1" do
    test "roundtrip using the application encryption password" do
      plaintext = "application-level secret"
      encrypted = Encryption.encrypt(plaintext)
      assert is_binary(encrypted)
      assert {:ok, ^plaintext} = Encryption.decrypt(encrypted)
    end

    test "encrypt returns a different ciphertext each call" do
      plaintext = "same value"
      enc1 = Encryption.encrypt(plaintext)
      enc2 = Encryption.encrypt(plaintext)
      refute enc1 == enc2
    end

    test "decrypt returns {:ok, value} on success" do
      encrypted = Encryption.encrypt("hello")
      assert {:ok, "hello"} = Encryption.decrypt(encrypted)
    end

    test "decrypt returns {:error, reason} on invalid input" do
      assert {:error, _} = Encryption.decrypt("not_valid_base64!!!")
    end
  end
end
