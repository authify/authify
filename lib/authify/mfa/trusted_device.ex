defmodule Authify.MFA.TrustedDevice do
  @moduledoc """
  Schema for trusted devices that can skip TOTP verification for 30 days.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias Authify.Accounts.User

  schema "trusted_devices" do
    field :device_token, :string
    field :plaintext_token, :string, virtual: true
    field :device_name, :string
    field :ip_address, :string
    field :user_agent, :string
    field :last_used_at, :utc_datetime
    field :expires_at, :utc_datetime

    belongs_to :user, User

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(trusted_device, attrs) do
    trusted_device
    |> cast(attrs, [
      :device_token,
      :device_name,
      :ip_address,
      :user_agent,
      :last_used_at,
      :expires_at,
      :user_id
    ])
    |> validate_required([:device_token, :expires_at, :user_id])
    |> unique_constraint(:device_token)
    |> foreign_key_constraint(:user_id)
  end
end
