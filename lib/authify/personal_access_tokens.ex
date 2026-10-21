defmodule Authify.PersonalAccessTokens do
  @moduledoc """
  Context for managing personal access tokens.
  """

  import Ecto.Query, warn: false

  alias Authify.Accounts.PersonalAccessToken
  alias Authify.Repo

  @doc """
  Creates a personal access token for a user.
  """
  def create_personal_access_token(user, organization, attrs) do
    %PersonalAccessToken{}
    |> PersonalAccessToken.changeset(
      attrs
      |> Map.put("user_id", user.id)
      |> Map.put("organization_id", organization.id)
    )
    |> Repo.insert()
  end

  @doc """
  Lists personal access tokens for a user.
  """
  def list_personal_access_tokens(user) do
    from(p in PersonalAccessToken,
      where: p.user_id == ^user.id,
      order_by: [desc: p.inserted_at]
    )
    |> Repo.all()
    |> Repo.preload(:scopes)
  end

  @doc """
  Lists personal access tokens for an organization.

  Pass `user_id: id` to restrict the results to a single user's tokens.
  """
  def list_personal_access_tokens_in_organization(organization, opts \\ []) do
    query =
      from(p in PersonalAccessToken,
        where: p.organization_id == ^organization.id,
        order_by: [desc: p.inserted_at]
      )

    query =
      case Keyword.get(opts, :user_id) do
        nil -> query
        user_id -> from(p in query, where: p.user_id == ^user_id)
      end

    query
    |> Repo.all()
    |> Repo.preload(:scopes)
  end

  @doc """
  Gets a personal access token for a user.
  """
  def get_personal_access_token!(id, user) do
    from(p in PersonalAccessToken,
      where: p.id == ^id and p.user_id == ^user.id
    )
    |> Repo.one!()
  end

  @doc """
  Gets a personal access token by ID, scoped to an organization.

  Returns `nil` when the token does not exist in the organization.
  """
  def get_personal_access_token_in_organization(id, organization) do
    from(p in PersonalAccessToken,
      where: p.id == ^id and p.organization_id == ^organization.id,
      preload: [:scopes]
    )
    |> Repo.one()
  end

  @doc """
  Deletes a personal access token.
  """
  def delete_personal_access_token(token) do
    Repo.delete(token)
  end

  @doc """
  Changes a personal access token.
  """
  def change_personal_access_token(token, attrs \\ %{}) do
    PersonalAccessToken.changeset(token, attrs)
  end

  @doc """
  Authenticates a personal access token.

  Hashes the provided token and verifies it against stored hashes in the database.
  """
  def authenticate_personal_access_token(token_string) do
    case String.split(token_string, "_", parts: 3) do
      ["authify", "pat", _token] ->
        # Hash the incoming token
        token_hash = PersonalAccessToken.hash_token(token_string)

        # Query for the token by hash
        from(p in PersonalAccessToken,
          where:
            p.token == ^token_hash and
              p.is_active == true and
              (is_nil(p.expires_at) or p.expires_at > ^DateTime.utc_now()),
          preload: [:user, :organization, :scopes]
        )
        |> Repo.one()
        |> case do
          nil ->
            {:error, :invalid_token}

          token ->
            # Update last_used_at
            update_token_last_used(token)
            {:ok, token}
        end

      _ ->
        {:error, :invalid_token}
    end
  end

  defp update_token_last_used(token) do
    token
    |> Ecto.Changeset.change(last_used_at: DateTime.utc_now() |> DateTime.truncate(:second))
    |> Repo.update()
  end
end
