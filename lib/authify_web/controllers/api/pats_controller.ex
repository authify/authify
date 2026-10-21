defmodule AuthifyWeb.API.PatsController do
  @moduledoc """
  Management API endpoints for personal access token lifecycle management.

  Users can manage their own tokens with the `profile:read` and `profile:write`
  scopes. Organization administrators can manage tokens for other users in
  their organization with the `users:read` and `users:write` scopes.

  Token values are only returned once, in the create response.
  """

  use AuthifyWeb.API.BaseController

  alias Authify.Accounts
  alias Authify.Accounts.{PersonalAccessToken, User}
  alias Authify.PersonalAccessTokens
  alias AuthifyWeb.Helpers.AuditHelper

  @create_param_keys ~w(name description expires_at scopes)

  @doc """
  GET /{org_slug}/api/pats

  Lists the current user's personal access tokens. Administrators may pass a
  `user_id` query parameter to list another user's tokens.
  """
  def index(conn, params) do
    organization = conn.assigns.current_organization
    current_user = conn.assigns[:current_user]

    case parse_user_id(params["user_id"]) do
      nil ->
        list_own_tokens(conn, current_user)

      {:ok, user_id} ->
        list_user_tokens(conn, organization, current_user, user_id)

      :error ->
        render_error_response(
          conn,
          :bad_request,
          "invalid_request",
          "user_id must be an integer"
        )
    end
  end

  @doc """
  POST /{org_slug}/api/pats

  Creates a personal access token for the current user, or another user in the
  organization when `user_id` is provided and the caller is an administrator.
  """
  def create(conn, %{"personal_access_token" => params}) do
    organization = conn.assigns.current_organization
    current_user = conn.assigns[:current_user]
    scopes = requested_scopes(params)

    with {:ok, target_user, mode} <-
           resolve_target_user(conn, organization, current_user, params["user_id"]),
         :ok <- authorize_create(conn, target_user, mode, scopes),
         {:ok, pat} <-
           PersonalAccessTokens.create_personal_access_token(
             target_user,
             organization,
             build_attrs(params)
           ) do
      pat = Authify.Repo.preload(pat, :scopes)

      AuditHelper.log_personal_access_token_event(
        conn,
        :personal_access_token_created,
        pat,
        extra_metadata: audit_metadata(mode)
      )

      render_api_response(conn, token_resource(pat, include_token: true),
        resource_type: "personal_access_token",
        status: :created
      )
    else
      {:error, %Ecto.Changeset{} = changeset} ->
        AuditHelper.log_personal_access_token_failure(
          conn,
          :personal_access_token_created,
          changeset,
          extra_metadata: %{"source" => "api"}
        )

        render_validation_errors(conn, changeset)

      {:error, response} ->
        response
    end
  end

  def create(conn, _params) do
    render_error_response(
      conn,
      :bad_request,
      "invalid_request",
      "Request must include personal_access_token parameters"
    )
  end

  @doc """
  DELETE /{org_slug}/api/pats/:id

  Revokes a personal access token. Users may revoke their own tokens;
  administrators may revoke tokens belonging to other users in the organization.
  """
  def delete(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    current_user = conn.assigns[:current_user]

    case PersonalAccessTokens.get_personal_access_token_in_organization(id, organization) do
      nil ->
        render_error_response(
          conn,
          :not_found,
          "resource_not_found",
          "Personal access token not found in organization"
        )

      token ->
        if current_user && token.user_id == current_user.id do
          case ensure_scope(conn, "profile:write") do
            :ok -> delete_token(conn, token)
            {:error, response} -> response
          end
        else
          with :ok <- ensure_scope(conn, "users:write"),
               {:ok, target_user} <-
                 fetch_user_in_organization(conn, organization, token.user_id),
               :ok <- ensure_admin_actor(conn, target_user) do
            delete_token(conn, token)
          else
            {:error, response} -> response
          end
        end
    end
  end

  defp list_own_tokens(conn, %{id: id} = current_user) when not is_nil(id) do
    case ensure_scope(conn, "profile:read") do
      :ok ->
        current_user
        |> PersonalAccessTokens.list_personal_access_tokens()
        |> render_tokens(conn)

      {:error, response} ->
        response
    end
  end

  defp list_own_tokens(conn, _current_user) do
    render_error_response(
      conn,
      :bad_request,
      "invalid_request",
      "user_id is required when authenticating as an application"
    )
  end

  defp list_user_tokens(conn, organization, current_user, user_id) do
    if current_user && current_user.id == user_id do
      list_own_tokens(conn, current_user)
    else
      with :ok <- ensure_scope(conn, "users:read"),
           {:ok, target_user} <- fetch_user_in_organization(conn, organization, user_id),
           :ok <- ensure_admin_actor(conn, target_user) do
        organization
        |> PersonalAccessTokens.list_personal_access_tokens_in_organization(
          user_id: target_user.id
        )
        |> render_tokens(conn)
      else
        {:error, response} -> response
      end
    end
  end

  defp render_tokens(tokens, conn) do
    render_collection_response(conn, Enum.map(tokens, &token_resource/1),
      resource_type: "personal_access_token"
    )
  end

  defp delete_token(conn, token) do
    case PersonalAccessTokens.delete_personal_access_token(token) do
      {:ok, _deleted_token} ->
        AuditHelper.log_personal_access_token_event(
          conn,
          :personal_access_token_deleted,
          token,
          extra_metadata: %{"source" => "api"}
        )

        conn
        |> put_status(:no_content)
        |> json(%{})

      {:error, %Ecto.Changeset{} = changeset} ->
        render_validation_errors(conn, changeset)
    end
  end

  defp resolve_target_user(conn, organization, current_user, user_id_param) do
    case parse_user_id(user_id_param) do
      nil ->
        case current_user do
          %{id: nil} ->
            {:error,
             render_error_response(
               conn,
               :bad_request,
               "invalid_request",
               "user_id is required when authenticating as an application"
             )}

          %{id: _id} ->
            {:ok, current_user, :self}

          _ ->
            {:error,
             render_error_response(
               conn,
               :unprocessable_entity,
               "invalid_request",
               "Unable to determine the target user"
             )}
        end

      {:ok, user_id} ->
        case current_user do
          %{id: ^user_id} ->
            {:ok, current_user, :self}

          _ ->
            with {:ok, target_user} <-
                   fetch_user_in_organization(conn, organization, user_id) do
              {:ok, target_user, :admin}
            end
        end

      :error ->
        {:error,
         render_error_response(
           conn,
           :bad_request,
           "invalid_request",
           "user_id must be an integer"
         )}
    end
  end

  defp authorize_create(conn, _target_user, :self, scopes) do
    with :ok <- ensure_scope(conn, "profile:write") do
      ensure_scope_subset(conn, scopes)
    end
  end

  defp authorize_create(conn, target_user, :admin, _scopes) do
    with :ok <- ensure_scope(conn, "users:write") do
      ensure_admin_actor(conn, target_user)
    end
  end

  # A personal access token may only mint tokens with scopes it already holds.
  # Otherwise a narrowly scoped token could escalate its own privileges.
  #
  # Invalid scope names are left to the changeset so the caller receives a
  # standard 422 validation response instead of a scope error.
  defp ensure_scope_subset(conn, requested_scopes) do
    valid_scopes = PersonalAccessToken.valid_scopes()
    invalid_scopes = Enum.reject(requested_scopes, &(&1 in valid_scopes))

    if invalid_scopes == [] and conn.assigns[:token_type] == :personal_access_token do
      provided_scopes = conn.assigns[:current_scopes] || []
      unauthorized = Enum.reject(requested_scopes, &scope_covered_by?(&1, provided_scopes))

      case unauthorized do
        [] ->
          :ok

        scopes ->
          {:error,
           render_error_response(
             conn,
             :forbidden,
             "insufficient_scope",
             "A personal access token cannot grant scopes it does not have",
             %{requested: scopes, provided: provided_scopes}
           )}
      end
    else
      :ok
    end
  end

  defp scope_covered_by?(requested_scope, provided_scopes) do
    requested_scope in provided_scopes or
      (String.ends_with?(requested_scope, ":read") and
         String.replace_suffix(requested_scope, ":read", ":write") in provided_scopes)
  end

  defp ensure_admin_actor(conn, _target_user) do
    organization = conn.assigns.current_organization
    actor = conn.assigns[:current_user]

    cond do
      conn.assigns[:actor_type] == :application ->
        :ok

      match?(%User{}, actor) and User.admin?(actor, organization.id) ->
        :ok

      true ->
        {:error,
         render_error_response(
           conn,
           :forbidden,
           "insufficient_permissions",
           "Only organization administrators may manage tokens for other users"
         )}
    end
  end

  defp fetch_user_in_organization(conn, organization, user_id) do
    case Accounts.get_user_in_organization(user_id, organization.id) do
      nil ->
        {:error,
         render_error_response(
           conn,
           :not_found,
           "resource_not_found",
           "User not found in organization"
         )}

      user ->
        {:ok, user}
    end
  end

  defp build_attrs(params) do
    params
    |> Map.take(@create_param_keys)
    |> Map.put("scopes", requested_scopes(params))
  end

  defp requested_scopes(params) do
    case params["scopes"] do
      scopes when is_list(scopes) ->
        Enum.reject(scopes, &(&1 in [nil, ""]))

      scopes when is_binary(scopes) ->
        scopes
        |> String.split(" ")
        |> Enum.reject(&(&1 == ""))

      _ ->
        []
    end
  end

  defp parse_user_id(nil), do: nil
  defp parse_user_id(id) when is_integer(id), do: {:ok, id}

  defp parse_user_id(id) when is_binary(id) do
    case Integer.parse(id) do
      {value, ""} -> {:ok, value}
      _ -> :error
    end
  end

  defp parse_user_id(_id), do: :error

  defp token_resource(token, opts \\ []) do
    resource = %{
      id: token.id,
      user_id: token.user_id,
      organization_id: token.organization_id,
      name: token.name,
      description: token.description,
      scopes: PersonalAccessToken.scopes_list(token),
      expires_at: token.expires_at,
      last_used_at: token.last_used_at,
      is_active: token.is_active,
      inserted_at: token.inserted_at,
      updated_at: token.updated_at
    }

    if opts[:include_token] do
      Map.put(resource, :token, token.plaintext_token)
    else
      resource
    end
  end

  defp audit_metadata(:self), do: %{"source" => "api"}
  defp audit_metadata(:admin), do: %{"source" => "api", "admin_managed" => true}
end
