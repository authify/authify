defmodule Authify.MFA.TotpLockout do
  @moduledoc """
  Schema for tracking TOTP lockouts after failed verification attempts.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias Authify.Accounts.User

  schema "totp_lockouts" do
    field :locked_at, :utc_datetime
    field :locked_until, :utc_datetime
    field :failed_attempts, :integer, default: 0
    field :locked_by_ip, :string
    field :unlocked_at, :utc_datetime

    belongs_to :user, User
    belongs_to :unlocked_by_admin, User

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(totp_lockout, attrs) do
    totp_lockout
    |> cast(attrs, [
      :locked_at,
      :locked_until,
      :failed_attempts,
      :locked_by_ip,
      :unlocked_at,
      :user_id,
      :unlocked_by_admin_id
    ])
    |> validate_required([:locked_at, :locked_until, :user_id])
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:unlocked_by_admin_id)
  end
end
