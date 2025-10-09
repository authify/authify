defmodule Authify.OAuth.AccessToken do
  @moduledoc """
  Schema for OAuth2 access tokens. Tokens are generated securely and expire
  after 1 hour by default. Supports scope-based authorization and revocation.
  """
  use Ecto.Schema
  import Ecto.Changeset

  schema "access_tokens" do
    field :token, :string
    field :scopes, :string
    field :expires_at, :utc_datetime
    field :revoked_at, :utc_datetime

    belongs_to :application, Authify.OAuth.Application
    belongs_to :user, Authify.Accounts.User

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(access_token, attrs) do
    access_token
    |> cast(attrs, [:token, :scopes, :expires_at, :revoked_at, :application_id, :user_id])
    |> validate_required([:scopes, :application_id, :user_id])
    |> put_token()
    |> put_expires_at()
    |> unique_constraint(:token)
  end

  @doc false
  def management_api_changeset(access_token, attrs) do
    access_token
    |> cast(attrs, [:token, :scopes, :expires_at, :revoked_at, :application_id, :user_id])
    |> validate_required([:scopes, :application_id])
    |> put_token()
    |> put_expires_at()
    |> unique_constraint(:token)
  end

  defp put_token(%Ecto.Changeset{valid?: true} = changeset) do
    put_change(changeset, :token, generate_token())
  end

  defp put_token(changeset), do: changeset

  defp put_expires_at(%Ecto.Changeset{valid?: true} = changeset) do
    expires_at = DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.truncate(:second)
    put_change(changeset, :expires_at, expires_at)
  end

  defp put_expires_at(changeset), do: changeset

  defp generate_token do
    :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  end

  def expired?(%__MODULE__{expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end

  def revoked?(%__MODULE__{revoked_at: revoked_at}) do
    not is_nil(revoked_at)
  end

  def valid?(%__MODULE__{} = access_token) do
    not expired?(access_token) and not revoked?(access_token)
  end

  def revoke(changeset) do
    put_change(changeset, :revoked_at, DateTime.utc_now() |> DateTime.truncate(:second))
  end

  def scopes_list(%__MODULE__{scopes: scopes}) when is_binary(scopes) do
    String.split(scopes, " ") |> Enum.reject(&(&1 == ""))
  end

  def scopes_list(_), do: []
end
