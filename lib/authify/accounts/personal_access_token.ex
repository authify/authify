defmodule Authify.Accounts.PersonalAccessToken do
  @moduledoc """
  Schema for personal access tokens (PATs) that allow users to authenticate
  API requests. Tokens are hashed using SHA-256 and support scopes, expiration,
  and activity tracking. Default expiration is 1 year.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias Authify.Accounts.{Organization, Scope, User}

  schema "personal_access_tokens" do
    field :name, :string
    field :description, :string
    field :token, :string
    field :plaintext_token, :string, virtual: true
    field :last_used_at, :utc_datetime
    field :expires_at, :utc_datetime
    field :is_active, :boolean, default: true

    belongs_to :user, User
    belongs_to :organization, Organization

    has_many :scopes, Scope,
      foreign_key: :scopeable_id,
      where: [scopeable_type: "PersonalAccessToken"],
      on_replace: :delete

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(personal_access_token, attrs) do
    personal_access_token
    |> cast(attrs, [
      :name,
      :description,
      :expires_at,
      :is_active,
      :user_id,
      :organization_id,
      :last_used_at
    ])
    |> validate_required([:name, :user_id, :organization_id])
    |> validate_length(:name, min: 1, max: 100)
    |> validate_length(:description, max: 500)
    |> put_token()
    |> put_default_expiry()
    |> put_scopes(attrs)
    |> unique_constraint(:token)
  end

  @doc """
  Returns the list of valid scopes for personal access tokens.
  """
  def valid_scopes, do: Authify.Scopes.pat_scopes()

  @doc """
  Returns the scopes as a list of strings.
  """
  def scopes_list(%__MODULE__{} = token) do
    if Ecto.assoc_loaded?(token.scopes) do
      Enum.map(token.scopes, & &1.scope)
    else
      []
    end
  end

  @doc """
  Checks if the token has a specific scope.
  """
  def has_scope?(%__MODULE__{} = token, scope) do
    scope in scopes_list(token)
  end

  @doc """
  Checks if the token is valid (active and not expired).
  """
  def valid?(%__MODULE__{is_active: false}), do: false
  def valid?(%__MODULE__{expires_at: nil}), do: true

  def valid?(%__MODULE__{expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :lt
  end

  @doc """
  Updates the last_used_at timestamp.
  """
  def touch_last_used(%__MODULE__{} = token) do
    token
    |> changeset(%{last_used_at: DateTime.utc_now()})
  end

  defp put_scopes(changeset, attrs) do
    scopes = get_scopes_from_attrs(attrs)

    if scopes == [] do
      add_error(changeset, :scopes, "can't be blank")
    else
      # Validate all scopes are valid
      invalid_scopes = Enum.reject(scopes, &(&1 in valid_scopes()))

      if invalid_scopes != [] do
        add_error(
          changeset,
          :scopes,
          "contains invalid scopes: #{Enum.join(invalid_scopes, ", ")}"
        )
      else
        # Build scope associations
        scope_structs =
          Enum.map(scopes, fn scope ->
            %Scope{
              scope: scope,
              scopeable_type: "PersonalAccessToken"
            }
          end)

        put_assoc(changeset, :scopes, scope_structs)
      end
    end
  end

  defp get_scopes_from_attrs(attrs) do
    cond do
      # List of scopes from form checkboxes
      is_list(attrs["scopes"]) ->
        attrs["scopes"] |> Enum.reject(&(&1 == ""))

      # Space-separated string (legacy or API)
      is_binary(attrs["scopes"]) ->
        attrs["scopes"] |> String.split(" ") |> Enum.reject(&(&1 == ""))

      # Atom key
      is_list(attrs[:scopes]) ->
        attrs[:scopes] |> Enum.reject(&(&1 == ""))

      is_binary(attrs[:scopes]) ->
        attrs[:scopes] |> String.split(" ") |> Enum.reject(&(&1 == ""))

      true ->
        []
    end
  end

  defp put_token(changeset) do
    if get_field(changeset, :token) do
      changeset
    else
      plaintext_token = generate_token()
      token_hash = hash_token(plaintext_token)

      changeset
      |> put_change(:token, token_hash)
      |> put_change(:plaintext_token, plaintext_token)
    end
  end

  defp put_default_expiry(changeset) do
    if get_field(changeset, :expires_at) do
      changeset
    else
      # Default to 1 year from now
      expires_at = DateTime.utc_now() |> DateTime.add(365, :day) |> DateTime.truncate(:second)
      put_change(changeset, :expires_at, expires_at)
    end
  end

  defp generate_token do
    # Generate a secure random token
    token =
      :crypto.strong_rand_bytes(32)
      |> Base.url_encode64(padding: false)
      # Truncate to 40 characters
      |> binary_part(0, 40)

    "authify_pat_#{token}"
  end

  @doc """
  Hashes a personal access token for secure storage.
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
