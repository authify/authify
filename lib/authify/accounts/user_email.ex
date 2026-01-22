defmodule Authify.Accounts.UserEmail do
  @moduledoc """
  Schema for user email addresses.

  Users can have multiple email addresses, but exactly one must be marked as primary.
  The primary email is used for authentication and primary communication.

  Email addresses are globally unique across the system.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias Authify.Accounts.User

  schema "user_emails" do
    field :value, :string
    field :type, :string, default: "work"
    field :primary, :boolean, default: false
    field :display, :string
    field :verified_at, :utc_datetime
    field :verification_token, :string
    field :verification_expires_at, :utc_datetime

    belongs_to :user, User

    timestamps()
  end

  @doc """
  Changeset for creating or updating a user email.
  Used when directly creating/updating emails (not via cast_assoc).
  """
  def changeset(user_email, attrs) do
    user_email
    |> cast(attrs, [
      :value,
      :type,
      :primary,
      :display,
      :verified_at,
      :verification_token,
      :verification_expires_at,
      :user_id
    ])
    |> validate_required([:value, :user_id])
    |> validate_email_format()
    |> validate_inclusion(:type, ["work", "home", "other"])
    |> unique_constraint(:value, message: "email address is already in use")

    # Note: Primary email uniqueness is validated at User level via validate_has_primary_email/1
    # MySQL doesn't support partial unique indexes, so we enforce this in application logic
  end

  @doc """
  Changeset for creating user emails via cast_assoc from User.
  Doesn't require user_id because Ecto sets it automatically from the parent.
  """
  def nested_changeset(user_email, attrs) do
    user_email
    |> cast(attrs, [
      :value,
      :type,
      :primary,
      :display,
      :verified_at
    ])
    |> validate_required([:value])
    |> validate_email_format()
    |> validate_inclusion(:type, ["work", "home", "other"])
    |> unique_constraint(:value, message: "email address is already in use")
  end

  @doc """
  Changeset for marking an email as verified.

  Clears verification token and sets verified_at timestamp.
  """
  def verify_changeset(user_email) do
    change(user_email, %{
      verified_at: DateTime.utc_now() |> DateTime.truncate(:second),
      verification_token: nil,
      verification_expires_at: nil
    })
  end

  @doc """
  Changeset for setting verification token on an email.
  """
  def verification_token_changeset(user_email, token) do
    expires_at =
      DateTime.utc_now()
      |> DateTime.add(24 * 60 * 60, :second)
      |> DateTime.truncate(:second)

    # Hash the token for storage
    hashed_token = :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)

    change(user_email, %{
      verification_token: hashed_token,
      verification_expires_at: expires_at
    })
  end

  # Validates email format
  defp validate_email_format(changeset) do
    changeset
    |> validate_format(:value, ~r/^[^\s]+@[^\s]+\.[^\s]+$/, message: "has invalid format")
    |> validate_length(:value, max: 160)
  end
end
