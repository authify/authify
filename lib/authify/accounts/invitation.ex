defmodule Authify.Accounts.Invitation do
  @moduledoc """
  Schema for user invitations to organizations. Invitations are sent via email
  with a secure token and expire after 7 days. Tracks invitation status and
  supports role assignment (user or admin).
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias Authify.Accounts.{Organization, User}

  @type t :: %__MODULE__{
          id: integer(),
          email: String.t(),
          token: String.t(),
          role: String.t(),
          expires_at: DateTime.t(),
          accepted_at: DateTime.t() | nil,
          organization_id: integer(),
          organization: Organization.t(),
          invited_by_id: integer(),
          invited_by: User.t(),
          inserted_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  @derive {Jason.Encoder, only: [:id, :email, :role, :expires_at, :accepted_at]}
  @primary_key {:id, :id, autogenerate: true}
  @foreign_key_type :id

  schema "invitations" do
    field :email, :string
    field :token, :string
    field :role, :string, default: "user"
    field :expires_at, :utc_datetime
    field :accepted_at, :utc_datetime

    belongs_to :organization, Organization
    belongs_to :invited_by, User

    timestamps(type: :utc_datetime)
  end

  @required_fields [:email, :role, :organization_id, :invited_by_id]
  @optional_fields [:token, :expires_at, :accepted_at]

  @doc false
  def changeset(invitation, attrs) do
    invitation
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_email(:email)
    |> validate_inclusion(:role, ["user", "admin"])
    |> unique_constraint([:email, :organization_id],
      message: "User already invited to this organization"
    )
    |> unique_constraint(:token)
    |> put_token()
    |> put_expires_at()
  end

  @doc false
  def accept_changeset(invitation, attrs) do
    invitation
    |> cast(attrs, [:accepted_at])
    |> validate_required([:accepted_at])
    |> validate_not_expired()
  end

  defp validate_email(changeset, field) do
    changeset
    |> validate_format(field, ~r/^[^\s]+@[^\s]+\.[^\s]+$/, message: "must be a valid email")
    |> validate_length(field, max: 160)
  end

  defp put_token(changeset) do
    case get_field(changeset, :token) do
      nil -> put_change(changeset, :token, generate_token())
      _ -> changeset
    end
  end

  defp put_expires_at(changeset) do
    case get_field(changeset, :expires_at) do
      nil ->
        expires_at = DateTime.utc_now() |> DateTime.add(7, :day) |> DateTime.truncate(:second)
        put_change(changeset, :expires_at, expires_at)

      _ ->
        changeset
    end
  end

  defp validate_not_expired(changeset) do
    case get_field(changeset, :expires_at) do
      nil ->
        changeset

      expires_at ->
        if DateTime.before?(expires_at, DateTime.utc_now()) do
          add_error(changeset, :expires_at, "invitation has expired")
        else
          changeset
        end
    end
  end

  defp generate_token do
    32
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end

  @doc """
  Checks if an invitation is expired.
  """
  def expired?(%__MODULE__{expires_at: expires_at}) do
    DateTime.before?(expires_at, DateTime.utc_now())
  end

  @doc """
  Checks if an invitation has been accepted.
  """
  def accepted?(%__MODULE__{accepted_at: nil}), do: false
  def accepted?(%__MODULE__{accepted_at: _}), do: true

  @doc """
  Checks if an invitation is still pending (not expired and not accepted).
  """
  def pending?(%__MODULE__{} = invitation) do
    not expired?(invitation) and not accepted?(invitation)
  end
end
