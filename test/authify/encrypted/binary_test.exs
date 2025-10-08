defmodule Authify.Encrypted.BinaryTest do
  use ExUnit.Case, async: true

  alias Authify.Encrypted.Binary

  describe "type/0" do
    test "returns :text" do
      assert Binary.type() == :text
    end
  end

  describe "cast/1" do
    test "accepts binary values" do
      assert Binary.cast("secret_value") == {:ok, "secret_value"}
    end

    test "accepts nil" do
      assert Binary.cast(nil) == {:ok, nil}
    end

    test "rejects non-binary values" do
      assert Binary.cast(123) == :error
      assert Binary.cast(%{}) == :error
      assert Binary.cast([]) == :error
    end
  end

  describe "dump/1" do
    test "encrypts binary values" do
      {:ok, encrypted} = Binary.dump("secret_value")

      # Should not be the original value
      refute encrypted == "secret_value"

      # Should be base64 encoded (encrypted format)
      assert String.match?(encrypted, ~r/^[A-Za-z0-9+\/]+=*$/)
    end

    test "returns nil for nil" do
      assert Binary.dump(nil) == {:ok, nil}
    end

    test "returns nil for empty string" do
      assert Binary.dump("") == {:ok, nil}
    end

    test "produces different encrypted values for same input (due to random IV)" do
      {:ok, encrypted1} = Binary.dump("secret_value")
      {:ok, encrypted2} = Binary.dump("secret_value")

      # Different encrypted values (different IVs)
      refute encrypted1 == encrypted2
    end
  end

  describe "load/1" do
    test "decrypts encrypted values" do
      original_value = "secret_value"
      {:ok, encrypted} = Binary.dump(original_value)
      {:ok, decrypted} = Binary.load(encrypted)

      assert decrypted == original_value
    end

    test "returns nil for nil" do
      assert Binary.load(nil) == {:ok, nil}
    end

    test "returns nil for empty string" do
      assert Binary.load("") == {:ok, nil}
    end

    test "returns error for invalid encrypted data" do
      assert {:error, _} = Binary.load("not_valid_encrypted_data")
    end
  end

  describe "equal?/2" do
    test "returns true for equal values" do
      assert Binary.equal?("value1", "value1")
      assert Binary.equal?(nil, nil)
    end

    test "returns false for different values" do
      refute Binary.equal?("value1", "value2")
      refute Binary.equal?("value1", nil)
      refute Binary.equal?(nil, "value1")
    end
  end

  describe "round-trip encryption/decryption" do
    test "encrypts and decrypts successfully" do
      original = "my_secret_password_123"

      # Simulate Ecto dump (to database)
      {:ok, encrypted} = Binary.dump(original)

      # Simulate Ecto load (from database)
      {:ok, decrypted} = Binary.load(encrypted)

      assert decrypted == original
      refute encrypted == original
    end

    test "handles unicode characters" do
      original = "секретный пароль 🔐"

      {:ok, encrypted} = Binary.dump(original)
      {:ok, decrypted} = Binary.load(encrypted)

      assert decrypted == original
    end

    test "handles long values" do
      original = String.duplicate("a", 10_000)

      {:ok, encrypted} = Binary.dump(original)
      {:ok, decrypted} = Binary.load(encrypted)

      assert decrypted == original
    end
  end
end
