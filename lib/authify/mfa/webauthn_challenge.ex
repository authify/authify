defmodule Authify.MFA.WebAuthnChallenge do
  @moduledoc """
  Schema for WebAuthn challenges used during registration and authentication.

  Challenges expire after 5 minutes and are consumed after successful use.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias Authify.Accounts.User

  @challenge_types ["registration", "authentication"]
  @challenge_expiry_minutes 5

  schema "webauthn_challenges" do
    field :challenge, :string
    field :challenge_type, :string
    field :expires_at, :utc_datetime
    field :consumed_at, :utc_datetime
    field :ip_address, :string
    field :user_agent, :string

    belongs_to :user, User

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(challenge, attrs) do
    challenge
    |> cast(attrs, [
      :challenge,
      :challenge_type,
      :expires_at,
      :consumed_at,
      :ip_address,
      :user_agent,
      :user_id
    ])
    |> validate_required([:challenge, :challenge_type, :expires_at, :user_id])
    |> validate_inclusion(:challenge_type, @challenge_types)
    |> validate_length(:challenge, max: 255)
    |> foreign_key_constraint(:user_id)
  end

  @doc """
  Returns true if the challenge has expired.
  """
  def expired?(%__MODULE__{expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end

  @doc """
  Returns true if the challenge has been consumed.
  """
  def consumed?(%__MODULE__{consumed_at: nil}), do: false
  def consumed?(%__MODULE__{consumed_at: _}), do: true

  @doc """
  Returns true if the challenge is valid (not expired and not consumed).
  """
  def valid?(%__MODULE__{} = challenge) do
    !expired?(challenge) && !consumed?(challenge)
  end

  @doc """
  Returns the list of valid challenge types.
  """
  def challenge_type_values, do: @challenge_types

  @doc """
  Returns the challenge expiry duration in minutes.
  """
  def expiry_minutes, do: @challenge_expiry_minutes

  @doc """
  Calculates the expiry datetime for a new challenge.
  Truncates to seconds for :utc_datetime compatibility.
  """
  def calculate_expiry do
    DateTime.utc_now()
    |> DateTime.add(@challenge_expiry_minutes * 60, :second)
    |> DateTime.truncate(:second)
  end
end
