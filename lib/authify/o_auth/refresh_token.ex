defmodule Authify.OAuth.RefreshToken do
  @moduledoc """
  Schema for OAuth2 refresh tokens.
  Refresh tokens allow clients to obtain new access tokens without user interaction.
  """
  use Ecto.Schema
  import Ecto.Changeset

  schema "refresh_tokens" do
    field :token, :string
    field :plaintext_token, :string, virtual: true
    field :scopes, :string
    field :expires_at, :utc_datetime
    field :revoked_at, :utc_datetime
    # OIDC nonce — propagated from the original authorization code
    field :nonce, :string
    # Groups a token with all of its rotations for reuse detection.
    field :token_family_id, :string
    # Why the token was revoked: "rotated", "manual", "password_change",
    # "family_reuse", etc. Lets reuse detection tell a replayed rotated token
    # apart from a deliberately revoked one.
    field :revoke_reason, :string

    belongs_to :application, Authify.OAuth.Application
    belongs_to :user, Authify.Accounts.User
    belongs_to :access_token, Authify.OAuth.AccessToken

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(refresh_token, attrs) do
    refresh_token
    |> cast(attrs, [
      :token,
      :scopes,
      :expires_at,
      :revoked_at,
      :nonce,
      :token_family_id,
      :revoke_reason,
      :application_id,
      :user_id,
      :access_token_id
    ])
    |> validate_required([:scopes, :application_id, :user_id])
    |> validate_length(:nonce, max: 2048)
    |> put_token()
    |> put_expires_at()
    |> unique_constraint(:token)
  end

  defp put_token(%Ecto.Changeset{valid?: true} = changeset) do
    case get_change(changeset, :token) do
      nil ->
        plaintext_token = generate_token()
        token_hash = hash_token(plaintext_token)

        changeset
        |> put_change(:token, token_hash)
        |> put_change(:plaintext_token, plaintext_token)

      _existing ->
        changeset
    end
  end

  defp put_token(changeset), do: changeset

  defp put_expires_at(%Ecto.Changeset{valid?: true} = changeset) do
    case get_change(changeset, :expires_at) do
      nil ->
        # Refresh tokens last 30 days by default
        expires_at =
          DateTime.utc_now()
          |> DateTime.add(30 * 24 * 60 * 60, :second)
          |> DateTime.truncate(:second)

        put_change(changeset, :expires_at, expires_at)

      _existing_expires_at ->
        changeset
    end
  end

  defp put_expires_at(changeset), do: changeset

  @doc """
  Generates a new, opaque token family identifier.
  """
  def generate_family_id do
    :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)
  end

  defp generate_token do
    :crypto.strong_rand_bytes(48) |> Base.url_encode64(padding: false)
  end

  @doc """
  Checks if a refresh token is expired.
  """
  def expired?(%__MODULE__{expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end

  @doc """
  Checks if a refresh token has been revoked.
  """
  def revoked?(%__MODULE__{revoked_at: revoked_at}) do
    not is_nil(revoked_at)
  end

  @doc """
  Checks if a refresh token is valid for use.
  """
  def valid?(%__MODULE__{} = refresh_token) do
    not expired?(refresh_token) and not revoked?(refresh_token)
  end

  @doc """
  Marks a refresh token as revoked.

  `reason` records why it was revoked (e.g. `"manual"`, `"password_change"`) so
  reuse detection can distinguish a deliberate revocation from a rotated token
  that was then replayed.
  """
  def revoke(changeset, reason \\ nil) do
    changeset
    |> put_change(:revoked_at, DateTime.utc_now() |> DateTime.truncate(:second))
    |> maybe_put_revoke_reason(reason)
  end

  defp maybe_put_revoke_reason(changeset, nil), do: changeset

  defp maybe_put_revoke_reason(changeset, reason),
    do: put_change(changeset, :revoke_reason, reason)

  @doc """
  Returns the scopes as a list.
  """
  def scopes_list(%__MODULE__{scopes: scopes}) when is_binary(scopes) do
    String.split(scopes, " ") |> Enum.reject(&(&1 == ""))
  end

  def scopes_list(_), do: []

  @doc """
  Hashes a refresh token for secure storage.
  Uses SHA-256 for fast hashing (tokens are already random and long).
  """
  def hash_token(token) when is_binary(token) do
    :crypto.hash(:sha256, token)
    |> Base.encode64()
  end

  @doc """
  Verifies a plaintext token against a stored hash.
  Returns true if the token matches, false otherwise.
  """
  def verify_token(plaintext_token, token_hash)
      when is_binary(plaintext_token) and is_binary(token_hash) do
    computed_hash = hash_token(plaintext_token)
    Plug.Crypto.secure_compare(computed_hash, token_hash)
  end

  def verify_token(_, _), do: false
end
