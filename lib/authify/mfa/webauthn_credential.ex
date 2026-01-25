defmodule Authify.MFA.WebAuthnCredential do
  @moduledoc """
  Schema for WebAuthn/FIDO2 credentials.

  Supports both platform authenticators (Touch ID, Face ID, Windows Hello)
  and roaming authenticators (YubiKey, Titan Key, etc.).
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias Authify.Accounts.{Organization, User}

  @credential_types ["platform", "roaming"]

  schema "webauthn_credentials" do
    field :credential_id, :string
    field :public_key, :binary
    field :sign_count, :integer, default: 0
    field :credential_type, :string
    field :transports, :string
    field :aaguid, :binary
    field :name, :string
    field :last_used_at, :utc_datetime

    belongs_to :user, User
    belongs_to :organization, Organization

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(credential, attrs) do
    credential
    |> cast(attrs, [
      :credential_id,
      :public_key,
      :sign_count,
      :credential_type,
      :transports,
      :aaguid,
      :name,
      :last_used_at,
      :user_id,
      :organization_id
    ])
    |> validate_required([:credential_id, :public_key, :user_id, :organization_id])
    |> validate_inclusion(:credential_type, @credential_types)
    |> validate_length(:name, max: 255)
    |> validate_length(:credential_id, max: 512)
    |> validate_number(:sign_count, greater_than_or_equal_to: 0)
    |> unique_constraint(:credential_id)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:organization_id)
  end

  @doc """
  Returns the list of valid credential types.
  """
  def credential_type_values, do: @credential_types

  @doc """
  Formats the transports JSON into a human-readable list.
  """
  def format_transports(nil), do: "Unknown"

  def format_transports(transports) when is_binary(transports) do
    case Jason.decode(transports) do
      {:ok, list} when is_list(list) -> format_transports(list)
      _ -> "Unknown"
    end
  end

  def format_transports(transports) when is_list(transports) do
    Enum.map_join(transports, ", ", &String.capitalize/1)
  end

  def format_transports(_), do: "Unknown"
end
