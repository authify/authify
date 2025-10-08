defmodule Authify.Encrypted.Binary do
  @moduledoc """
  Custom Ecto type for transparent encryption/decryption of binary data.

  This type automatically encrypts data before storing it in the database
  and decrypts it when loading from the database.

  ## Usage

      schema "my_table" do
        field :secret_field, Authify.Encrypted.Binary
      end

  The field will be stored as encrypted text in the database but will
  appear as plaintext when accessed in your application code.
  """

  use Ecto.Type

  @impl true
  def type, do: :text

  @impl true
  def cast(value) when is_binary(value), do: {:ok, value}
  def cast(nil), do: {:ok, nil}
  def cast(_), do: :error

  @impl true
  def dump(nil), do: {:ok, nil}
  def dump(""), do: {:ok, nil}

  def dump(value) when is_binary(value) do
    # Encrypt the value before storing
    encrypted = Authify.Encryption.encrypt(value)
    {:ok, encrypted}
  rescue
    error ->
      {:error, "Failed to encrypt value: #{inspect(error)}"}
  end

  @impl true
  def load(nil), do: {:ok, nil}
  def load(""), do: {:ok, nil}

  def load(value) when is_binary(value) do
    # Decrypt the value when loading from database
    case Authify.Encryption.decrypt(value) do
      {:ok, decrypted} -> {:ok, decrypted}
      {:error, reason} -> {:error, "Failed to decrypt value: #{reason}"}
    end
  end

  @impl true
  def equal?(value1, value2), do: value1 == value2
end
