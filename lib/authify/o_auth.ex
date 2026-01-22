defmodule Authify.OAuth do
  @moduledoc """
  The OAuth context for handling OAuth2 and OIDC functionality.
  """

  import Ecto.Query, warn: false
  alias Authify.Repo

  alias Authify.Accounts.{Organization, User}
  alias Authify.OAuth.{AccessToken, Application, AuthorizationCode, RefreshToken}

  @doc """
  Returns the list of applications for an organization.
  """
  def list_applications(%Organization{id: org_id}) do
    Application
    |> where([a], a.organization_id == ^org_id)
    |> order_by([a], desc: a.inserted_at)
    |> Repo.all()
    |> Repo.preload(:scopes)
  end

  @doc """
  Returns the list of OAuth applications for an organization (excludes Management API apps).
  """
  def list_oauth_applications(%Organization{id: org_id}) do
    Application
    |> where([a], a.organization_id == ^org_id and a.application_type == "oauth2_app")
    |> order_by([a], desc: a.inserted_at)
    |> Repo.all()
    |> Repo.preload(:scopes)
  end

  @doc """
  Returns a filtered and sorted list of OAuth applications for an organization.

  ## Options
    * `:sort` - Field to sort by (atom, e.g., :name, :inserted_at)
    * `:order` - Sort order (:asc or :desc, defaults to :desc)
    * `:search` - Text search across name field
    * `:status` - Filter by active status (boolean or "all")

  ## Examples

      iex> list_oauth_applications_filtered(org, sort: :name, order: :asc, search: "app")
      [%Application{}, ...]
  """
  def list_oauth_applications_filtered(%Organization{id: org_id}, opts \\ []) do
    query =
      from(a in Application,
        where: a.organization_id == ^org_id and a.application_type == "oauth2_app"
      )

    query
    |> apply_application_filters(opts)
    |> apply_application_search(opts[:search])
    |> apply_application_sorting(opts[:sort], opts[:order])
    |> Repo.all()
    |> Repo.preload(:scopes)
  end

  defp apply_application_filters(query, opts) do
    maybe_filter_application_by_status(query, opts[:status])
  end

  defp maybe_filter_application_by_status(query, nil), do: where(query, [a], a.is_active == true)
  defp maybe_filter_application_by_status(query, ""), do: where(query, [a], a.is_active == true)
  defp maybe_filter_application_by_status(query, "all"), do: query
  defp maybe_filter_application_by_status(query, true), do: where(query, [a], a.is_active == true)

  defp maybe_filter_application_by_status(query, "true"),
    do: where(query, [a], a.is_active == true)

  defp maybe_filter_application_by_status(query, false),
    do: where(query, [a], a.is_active == false)

  defp maybe_filter_application_by_status(query, "false"),
    do: where(query, [a], a.is_active == false)

  defp maybe_filter_application_by_status(query, _), do: where(query, [a], a.is_active == true)

  defp apply_application_search(query, nil), do: query
  defp apply_application_search(query, ""), do: query

  defp apply_application_search(query, search_term) when is_binary(search_term) do
    search_pattern = "%#{search_term}%"
    where(query, [a], like(a.name, ^search_pattern))
  end

  defp apply_application_sorting(query, nil, _), do: order_by(query, [a], desc: a.inserted_at)
  defp apply_application_sorting(query, "", _), do: order_by(query, [a], desc: a.inserted_at)

  defp apply_application_sorting(query, sort_field, order)
       when sort_field in [:name, :client_id, :inserted_at, :updated_at] do
    order_atom = if order == :asc or order == "asc", do: :asc, else: :desc
    order_by(query, [a], ^[{order_atom, sort_field}])
  end

  defp apply_application_sorting(query, _sort_field, _order),
    do: order_by(query, [a], desc: a.inserted_at)

  @doc """
  Returns the list of Management API applications for an organization.
  """
  def list_management_api_applications(%Organization{id: org_id}) do
    Application
    |> where([a], a.organization_id == ^org_id and a.application_type == "management_api_app")
    |> order_by([a], desc: a.inserted_at)
    |> Repo.all()
    |> Repo.preload(:scopes)
  end

  @doc """
  Returns a paginated list of applications for an organization.
  """
  def list_applications(%Organization{id: org_id}, opts) do
    page = opts[:page] || 1
    per_page = opts[:per_page] || 25
    offset = (page - 1) * per_page

    applications =
      Application
      |> where([a], a.organization_id == ^org_id)
      |> order_by([a], desc: a.inserted_at)
      |> limit(^per_page)
      |> offset(^offset)
      |> Repo.all()

    total =
      Application
      |> where([a], a.organization_id == ^org_id)
      |> Repo.aggregate(:count, :id)

    {applications, total}
  end

  @doc """
  Returns a paginated list of OAuth applications for an organization (excludes Management API apps).
  """
  def list_oauth_applications(%Organization{id: org_id}, opts) do
    page = opts[:page] || 1
    per_page = opts[:per_page] || 25
    offset = (page - 1) * per_page

    applications =
      Application
      |> where([a], a.organization_id == ^org_id and a.application_type == "oauth2_app")
      |> order_by([a], desc: a.inserted_at)
      |> limit(^per_page)
      |> offset(^offset)
      |> Repo.all()

    total =
      Application
      |> where([a], a.organization_id == ^org_id and a.application_type == "oauth2_app")
      |> Repo.aggregate(:count, :id)

    {applications, total}
  end

  @doc """
  Returns a paginated list of applications for an organization, filtered by allowed types.

  ## Parameters
    * `organization` - The organization to list applications for
    * `allowed_types` - List of application types to include (e.g., ["oauth2_app", "management_api_app"])
    * `opts` - Pagination options (:page, :per_page)
  """
  def list_all_applications(%Organization{id: org_id}, allowed_types, opts)
      when is_list(allowed_types) do
    page = opts[:page] || 1
    per_page = opts[:per_page] || 25
    offset = (page - 1) * per_page

    applications =
      Application
      |> where([a], a.organization_id == ^org_id and a.application_type in ^allowed_types)
      |> order_by([a], desc: a.inserted_at)
      |> limit(^per_page)
      |> offset(^offset)
      |> Repo.all()

    total =
      Application
      |> where([a], a.organization_id == ^org_id and a.application_type in ^allowed_types)
      |> Repo.aggregate(:count, :id)

    {applications, total}
  end

  @doc """
  Returns a paginated list of Management API applications for an organization.
  """
  def list_management_api_applications(%Organization{id: org_id}, opts) do
    page = opts[:page] || 1
    per_page = opts[:per_page] || 25
    offset = (page - 1) * per_page

    applications =
      Application
      |> where([a], a.organization_id == ^org_id and a.application_type == "management_api_app")
      |> order_by([a], desc: a.inserted_at)
      |> limit(^per_page)
      |> offset(^offset)
      |> Repo.all()

    total =
      Application
      |> where([a], a.organization_id == ^org_id and a.application_type == "management_api_app")
      |> Repo.aggregate(:count, :id)

    {applications, total}
  end

  @doc """
  Gets a single application by ID within an organization.
  """
  def get_application!(id, %Organization{id: org_id}) do
    Application
    |> where([a], a.id == ^id and a.organization_id == ^org_id)
    |> Repo.one!()
    |> Repo.preload(:scopes)
  end

  @doc """
  Gets a single OAuth application by ID within an organization (excludes Management API apps).
  """
  def get_oauth_application!(id, %Organization{id: org_id}) do
    Application
    |> where(
      [a],
      a.id == ^id and a.organization_id == ^org_id and a.application_type == "oauth2_app"
    )
    |> Repo.one!()
    |> Repo.preload(:scopes)
  end

  @doc """
  Gets a single Management API application by ID within an organization.
  """
  def get_management_api_application!(id, %Organization{id: org_id}) do
    Application
    |> where(
      [a],
      a.id == ^id and a.organization_id == ^org_id and a.application_type == "management_api_app"
    )
    |> Repo.one!()
    |> Repo.preload(:scopes)
  end

  @doc """
  Gets a single application by ID.
  """
  def get_application!(id) do
    Repo.get!(Application, id)
    |> Repo.preload(:scopes)
  end

  @doc """
  Gets a single application by client_id (not organization-scoped).

  WARNING: This function does not validate organization membership.
  Use `get_application_by_client_id/2` when you have an organization context.
  """
  def get_application_by_client_id(client_id) do
    Application
    |> where([a], a.client_id == ^client_id and a.is_active == true)
    |> Repo.one()
    |> case do
      nil -> nil
      app -> Repo.preload(app, :scopes)
    end
  end

  @doc """
  Gets a single application by client_id within a specific organization.

  This is the secure version that validates the application belongs to the organization.
  """
  def get_application_by_client_id(client_id, %Organization{id: org_id}) do
    Application
    |> where(
      [a],
      a.client_id == ^client_id and a.organization_id == ^org_id and a.is_active == true
    )
    |> Repo.one()
    |> case do
      nil -> nil
      app -> Repo.preload(app, :scopes)
    end
  end

  @doc """
  Creates an application.
  """
  def create_application(attrs \\ %{}) do
    %Application{}
    |> Application.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates an application.
  """
  def update_application(%Application{} = application, attrs) do
    application
    |> Application.update_changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes an application.
  """
  def delete_application(%Application{} = application) do
    Repo.delete(application)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking application changes.
  """
  def change_application(%Application{} = application, attrs \\ %{}) do
    Application.changeset(application, attrs)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking application form changes without validation.
  """
  def change_application_form(%Application{} = application, attrs \\ %{}) do
    Application.form_changeset(application, attrs)
  end

  @doc """
  Creates an authorization code for the OAuth2 flow.
  Supports PKCE parameters (code_challenge and code_challenge_method).

  Validates that the user and application belong to the same organization
  for multi-tenant security.
  """
  def create_authorization_code(application, user, redirect_uri, scopes, pkce_params \\ %{})

  def create_authorization_code(
        %Application{organization_id: org_id} = application,
        %User{organization_id: org_id} = user,
        redirect_uri,
        scopes,
        pkce_params
      ) do
    attrs =
      %{
        application_id: application.id,
        user_id: user.id,
        redirect_uri: redirect_uri,
        scopes: Enum.join(scopes, " ")
      }
      |> Map.merge(pkce_params)

    %AuthorizationCode{}
    |> AuthorizationCode.changeset(attrs)
    |> Repo.insert()
  end

  def create_authorization_code(%Application{}, %User{}, _, _, _) do
    {:error, :organization_mismatch}
  end

  @doc """
  Gets an authorization code by its code value.
  """
  def get_authorization_code(code) do
    AuthorizationCode
    |> where([ac], ac.code == ^code)
    |> preload([:application, :user])
    |> Repo.one()
  end

  @doc """
  Exchanges an authorization code for an access token.
  Also creates a refresh token if the application supports the refresh_token grant type.
  """
  def exchange_authorization_code(%AuthorizationCode{} = auth_code, %Application{} = application) do
    if AuthorizationCode.valid_for_exchange?(auth_code) and
         auth_code.application_id == application.id do
      Repo.transaction(fn ->
        # Mark the authorization code as used
        auth_code
        |> Ecto.Changeset.change()
        |> AuthorizationCode.mark_as_used()
        |> Repo.update!()

        # Create access token
        access_token_attrs = %{
          application_id: application.id,
          user_id: auth_code.user_id,
          scopes: auth_code.scopes
        }

        access_token =
          %AccessToken{}
          |> AccessToken.changeset(access_token_attrs)
          |> Repo.insert!()
          |> Repo.preload([:application, :user])

        # Create refresh token if supported
        refresh_token =
          if Application.supports_grant_type?(application, "refresh_token") do
            # Preload user if not already loaded
            user =
              if Ecto.assoc_loaded?(auth_code.user) do
                auth_code.user
              else
                Repo.get!(Authify.Accounts.User, auth_code.user_id)
              end

            {:ok, rt} =
              create_refresh_token(
                application,
                user,
                auth_code.scopes,
                access_token.id
              )

            rt
          else
            nil
          end

        %{access_token: access_token, refresh_token: refresh_token}
      end)
    else
      {:error, :invalid_authorization_code}
    end
  end

  @doc """
  Gets an access token by its token value.
  """
  def get_access_token(token) do
    AccessToken
    |> where([at], at.token == ^token)
    |> preload([:application, :user])
    |> Repo.one()
  end

  @doc """
  Validates an access token and returns the associated user if valid (not organization-scoped).

  WARNING: This function does not validate organization membership.
  Use `validate_access_token/2` when you have an organization context.
  """
  def validate_access_token(token) do
    case get_access_token(token) do
      %AccessToken{} = access_token ->
        if AccessToken.valid?(access_token) do
          {:ok, access_token}
        else
          {:error, :invalid_token}
        end

      nil ->
        {:error, :token_not_found}
    end
  end

  @doc """
  Validates an access token within a specific organization.

  This is the secure version that validates the token's application belongs to the organization.
  """
  def validate_access_token(token, %Organization{id: org_id}) do
    case get_access_token(token) do
      %AccessToken{application: %{organization_id: ^org_id}} = access_token ->
        if AccessToken.valid?(access_token) do
          {:ok, access_token}
        else
          {:error, :invalid_token}
        end

      %AccessToken{} ->
        # Token exists but belongs to different organization
        {:error, :invalid_token}

      nil ->
        {:error, :token_not_found}
    end
  end

  @doc """
  Revokes an access token.
  """
  def revoke_access_token(%AccessToken{} = access_token) do
    access_token
    |> Ecto.Changeset.change()
    |> AccessToken.revoke()
    |> Repo.update()
  end

  @doc """
  Creates an access token for Management API access via client credentials flow.
  This is used for API-to-API authentication without a specific user context.
  """
  def create_management_api_access_token(%Application{} = application, scopes) do
    # For now, we'll create a service-level access token without a specific user
    # In the future, we might want to support user-bound management API access
    attrs = %{
      scopes: scopes,
      application_id: application.id,
      # No user_id for service-level access
      user_id: nil
    }

    %AccessToken{}
    |> AccessToken.management_api_changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Lists access tokens for a user and application.
  """
  def list_access_tokens(%User{id: user_id}, %Application{id: app_id}) do
    AccessToken
    |> where([at], at.user_id == ^user_id and at.application_id == ^app_id)
    |> where([at], is_nil(at.revoked_at))
    |> order_by([at], desc: at.inserted_at)
    |> Repo.all()
  end

  @doc """
  Validates redirect URI against application's registered URIs.
  """
  def valid_redirect_uri?(%Application{} = application, redirect_uri) do
    registered_uris = Application.redirect_uris_list(application)
    redirect_uri in registered_uris
  end

  @doc """
  Validates scopes against application's registered scopes.
  """
  def valid_scopes?(%Application{} = application, requested_scopes) do
    app_scopes = Application.scopes_list(application)
    Enum.all?(requested_scopes, &(&1 in app_scopes))
  end

  @doc """
  Generates OIDC userinfo claims for a user based on requested scopes.
  """
  def generate_userinfo_claims(%User{} = user, scopes) do
    base_claims = %{"sub" => to_string(user.id)}

    scopes
    |> Enum.reduce(base_claims, &add_scope_claims(&1, &2, user))
  end

  defp add_scope_claims("profile", claims, user) do
    full_name = "#{user.first_name} #{user.last_name}" |> String.trim()

    Map.merge(claims, %{
      "name" => full_name,
      "given_name" => user.first_name,
      "family_name" => user.last_name,
      "preferred_username" => User.get_primary_email_value(user),
      "updated_at" => DateTime.to_unix(user.updated_at)
    })
  end

  defp add_scope_claims("email", claims, user) do
    Map.merge(claims, %{
      "email" => User.get_primary_email_value(user),
      "email_verified" => true
    })
  end

  defp add_scope_claims("groups", claims, user) do
    groups = get_user_groups(user)
    Map.put(claims, "groups", groups)
  end

  defp add_scope_claims(_, claims, _user), do: claims

  defp get_user_groups(%User{groups: groups}) when is_list(groups) do
    # Groups are already preloaded, extract names
    Enum.map(groups, & &1.name)
  end

  defp get_user_groups(%User{} = user) do
    # Groups not preloaded, fetch them
    user = Repo.preload(user, :groups)
    Enum.map(user.groups, & &1.name)
  end

  @doc """
  Cleanup expired authorization codes and access tokens.
  """
  def cleanup_expired_tokens do
    now = DateTime.utc_now()

    # Delete expired authorization codes
    expired_codes_query =
      from(ac in AuthorizationCode,
        where: ac.expires_at < ^now
      )

    expired_codes_deleted = Repo.delete_all(expired_codes_query)

    # Delete expired access tokens
    expired_tokens_query =
      from(at in AccessToken,
        where: at.expires_at < ^now
      )

    expired_tokens_deleted = Repo.delete_all(expired_tokens_query)

    # Delete expired refresh tokens
    expired_refresh_tokens_query =
      from(rt in RefreshToken,
        where: rt.expires_at < ^now
      )

    expired_refresh_tokens_deleted = Repo.delete_all(expired_refresh_tokens_query)

    {:ok,
     %{
       authorization_codes: expired_codes_deleted,
       access_tokens: expired_tokens_deleted,
       refresh_tokens: expired_refresh_tokens_deleted
     }}
  end

  # Refresh Token functions

  @doc """
  Creates a refresh token for an application and user.
  """
  def create_refresh_token(
        %Application{} = application,
        %User{} = user,
        scopes,
        access_token_id \\ nil
      ) do
    attrs = %{
      application_id: application.id,
      user_id: user.id,
      scopes: scopes,
      access_token_id: access_token_id
    }

    %RefreshToken{}
    |> RefreshToken.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Gets a refresh token by its token value.
  Hashes the provided token and looks up by hash.
  """
  def get_refresh_token(token) do
    token_hash = RefreshToken.hash_token(token)

    RefreshToken
    |> where([rt], rt.token == ^token_hash)
    |> preload([:application, :user])
    |> Repo.one()
  end

  @doc """
  Exchanges a refresh token for a new access token.
  Optionally rotates the refresh token (recommended for security).
  """
  def exchange_refresh_token(%RefreshToken{} = refresh_token, rotate \\ true) do
    if RefreshToken.valid?(refresh_token) do
      Repo.transaction(fn ->
        # Create new access token
        access_token_attrs = %{
          application_id: refresh_token.application_id,
          user_id: refresh_token.user_id,
          scopes: refresh_token.scopes
        }

        access_token =
          %AccessToken{}
          |> AccessToken.changeset(access_token_attrs)
          |> Repo.insert!()
          |> Repo.preload([:application, :user])

        # Optionally rotate refresh token
        new_refresh_token =
          if rotate do
            # Revoke old refresh token
            refresh_token
            |> Ecto.Changeset.change()
            |> RefreshToken.revoke()
            |> Repo.update!()

            # Create new refresh token
            {:ok, new_rt} =
              create_refresh_token(
                refresh_token.application,
                refresh_token.user,
                refresh_token.scopes,
                access_token.id
              )

            new_rt
          else
            refresh_token
          end

        %{access_token: access_token, refresh_token: new_refresh_token}
      end)
    else
      {:error, :invalid_refresh_token}
    end
  end

  @doc """
  Revokes a refresh token.
  """
  def revoke_refresh_token(%RefreshToken{} = refresh_token) do
    refresh_token
    |> Ecto.Changeset.change()
    |> RefreshToken.revoke()
    |> Repo.update()
  end
end
