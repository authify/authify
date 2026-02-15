defmodule Authify.OAuth.UserGrant do
  @moduledoc """
  Schema for OAuth2 user grants that track persistent user consent.

  When a user authorizes an application, a grant is created to remember
  their consent. This allows the authorization server to skip the consent
  screen on subsequent authorization requests if the user has already
  granted the requested scopes.

  Grants can be revoked by the user at any time, requiring fresh consent
  for the next authorization attempt.
  """
  use Ecto.Schema
  import Ecto.Changeset

  schema "oauth_user_grants" do
    field :scopes, :string
    field :revoked_at, :utc_datetime

    belongs_to :user, Authify.Accounts.User
    belongs_to :application, Authify.OAuth.Application

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(user_grant, attrs) do
    user_grant
    |> cast(attrs, [:user_id, :application_id, :scopes, :revoked_at])
    |> validate_required([:user_id, :application_id])
    |> validate_scopes()
    |> unique_constraint([:user_id, :application_id],
      name: :oauth_user_grants_user_app_unique,
      message: "User has already granted this application"
    )
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:application_id)
  end

  @doc """
  Marks a grant as revoked by setting revoked_at timestamp.
  """
  def revoke(changeset) do
    put_change(changeset, :revoked_at, DateTime.utc_now() |> DateTime.truncate(:second))
  end

  @doc """
  Checks if a grant has been revoked.
  """
  def revoked?(%__MODULE__{revoked_at: revoked_at}) do
    not is_nil(revoked_at)
  end

  @doc """
  Parses the space-separated scopes string into a list.

  ## Examples

      iex> grant = %UserGrant{scopes: "openid profile email"}
      iex> UserGrant.scopes_list(grant)
      ["openid", "profile", "email"]
  """
  def scopes_list(%__MODULE__{scopes: scopes}) when is_binary(scopes) do
    String.split(scopes, " ") |> Enum.reject(&(&1 == ""))
  end

  def scopes_list(_), do: []

  @doc """
  Checks if the grant covers all requested scopes.

  Returns true if all requested scopes are present in the granted scopes,
  false otherwise.

  ## Examples

      iex> grant = %UserGrant{scopes: "openid profile email"}
      iex> UserGrant.scopes_match?(grant, ["openid", "profile"])
      true

      iex> grant = %UserGrant{scopes: "openid profile"}
      iex> UserGrant.scopes_match?(grant, ["openid", "profile", "email"])
      false
  """
  def scopes_match?(%__MODULE__{} = grant, requested_scopes) when is_list(requested_scopes) do
    granted_scopes = scopes_list(grant)
    # All requested scopes must be in granted scopes
    Enum.all?(requested_scopes, &(&1 in granted_scopes))
  end

  def scopes_match?(_, _), do: false

  # Private helper to validate scopes format
  defp validate_scopes(changeset) do
    case get_field(changeset, :scopes) do
      nil ->
        add_error(changeset, :scopes, "can't be blank")

      scopes when is_binary(scopes) ->
        if String.trim(scopes) == "" do
          add_error(changeset, :scopes, "cannot be empty")
        else
          changeset
        end

      _ ->
        add_error(changeset, :scopes, "must be a string")
    end
  end
end
