defmodule Authify.OAuth do
  @moduledoc """
  The OAuth context for handling OAuth2 and OIDC functionality.
  """

  import Ecto.Query, warn: false
  alias Authify.Accounts.{Organization, User}
  alias Authify.AuditLog
  alias Authify.FilterSort
  alias Authify.OAuth.{AccessToken, Application, AuthorizationCode, RefreshToken, UserGrant}
  alias Authify.Repo

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

  defp maybe_filter_application_by_status(query, status),
    do: FilterSort.apply_status_filter(query, :is_active, status)

  defp apply_application_search(query, search),
    do: FilterSort.apply_text_filter(query, :name, search)

  @application_sort_fields [:name, :client_id, :inserted_at, :updated_at]

  defp apply_application_sorting(query, sort, order),
    do:
      FilterSort.apply_sort(query, sort, order, @application_sort_fields,
        default: [desc: :inserted_at]
      )

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
      |> Repo.preload(:scopes)

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
      |> Repo.preload(:scopes)

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
      |> Repo.preload(:scopes)

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
      |> Repo.preload(:scopes)

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
  Replaces an application's client secret with `new_secret`.
  """
  def regenerate_application_secret(%Application{} = application, new_secret)
      when is_binary(new_secret) do
    application
    |> Application.regenerate_secret_changeset(new_secret)
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
                access_token.id,
                auth_code.nonce
              )

            Repo.preload(rt, [:application, :user])
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
    |> preload([:application, :user, user: :emails])
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
      "preferred_username" => user.username,
      "updated_at" => DateTime.to_unix(user.updated_at),
      "picture" => User.avatar_url(user),
      "locale" => user.locale,
      "zoneinfo" => user.zoneinfo,
      "website" => user.website,
      "team" => user.team,
      "title" => user.title
    })
    |> Map.reject(fn {_, v} -> is_nil(v) || v == "" end)
  end

  defp add_scope_claims("phone", claims, user) do
    Map.merge(claims, %{
      "phone_number" => user.phone_number,
      "phone_number_verified" => user.phone_number_verified || false
    })
    |> Map.reject(fn {_, v} -> is_nil(v) end)
  end

  defp add_scope_claims("email", claims, user) do
    Map.merge(claims, %{
      "email" => User.get_primary_email_value(user),
      "email_verified" => User.primary_email_verified?(user)
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
        access_token_id \\ nil,
        nonce \\ nil,
        token_family_id \\ nil
      ) do
    attrs = %{
      application_id: application.id,
      user_id: user.id,
      scopes: scopes,
      access_token_id: access_token_id,
      nonce: nonce,
      # A rotated token inherits its parent's family id; a fresh token (no family
      # id given) starts its own so it can be tracked for reuse detection.
      token_family_id:
        if(is_nil(token_family_id), do: RefreshToken.generate_family_id(), else: token_family_id)
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
    cond do
      RefreshToken.expired?(refresh_token) ->
        {:error, :invalid_refresh_token}

      not rotate ->
        # Preserve legacy behaviour: no consumption, no rotation, no reuse concept.
        if RefreshToken.valid?(refresh_token) do
          Repo.transaction(fn ->
            %{access_token: create_access_token(refresh_token), refresh_token: refresh_token}
          end)
        else
          {:error, :invalid_refresh_token}
        end

      true ->
        # Rotation with reuse detection.
        #
        # The old token is consumed with an *atomic conditional UPDATE*
        # (`WHERE id = ? AND revoked_at IS NULL`) instead of a read-then-write.
        # Under InnoDB the row update serializes concurrent transactions: exactly
        # one racer claims the row (`affected == 1`); the loser sees `0`, which is
        # itself the reuse signal. This closes the race where two requests present
        # the same live token and both pass a stale `valid?` check.
        refresh_token
        |> rotate_refresh_token()
        |> log_reuse_event()
        |> map_exchange_result()
    end
  end

  # Logs a detected-reuse audit event OUTSIDE the rotation transaction, so a
  # failed audit insert can never roll back the committed family revocation.
  # Logs, then returns the outcome unchanged so the public result is unaffected.
  defp log_reuse_event({:ok, %{event: attrs}} = outcome) when not is_nil(attrs),
    do:
      (
        AuditLog.log_event(:refresh_token_reuse_detected, attrs)
        outcome
      )

  defp log_reuse_event(outcome), do: outcome

  # Runs the rotation transaction and maps its outcome to the public result.
  #
  # The transaction itself always *succeeds* so that the revocation and any audit
  # event are committed — the reuse/invalid distinction is produced here at the
  # Elixir layer rather than via a rollback, which would discard the audit row.
  defp rotate_refresh_token(%RefreshToken{} = refresh_token) do
    Repo.transaction(fn ->
      now = DateTime.utc_now() |> DateTime.truncate(:second)

      {claimed, _} =
        Repo.update_all(
          from(rt in RefreshToken,
            where: rt.id == ^refresh_token.id and is_nil(rt.revoked_at)
          ),
          set: [revoked_at: now, revoke_reason: "rotated"]
        )

      case claimed do
        1 -> issue_rotated_tokens(refresh_token, now)
        _ -> handle_refresh_token_reuse(refresh_token, now)
      end
    end)
  end

  # Creates a fresh access token and a rotated refresh token for `refresh_token`.
  #
  # When the token belongs to a family the new refresh token inherits the family
  # id, so the family chain is preserved across rotations. When it has no family
  # id (a legacy row) the new token starts its own family.
  defp issue_rotated_tokens(%RefreshToken{} = refresh_token, _now) do
    access_token = create_access_token(refresh_token)

    {:ok, new_rt} =
      create_refresh_token(
        refresh_token.application,
        refresh_token.user,
        refresh_token.scopes,
        access_token.id,
        refresh_token.nonce,
        refresh_token.token_family_id
      )

    %{access_token: access_token, refresh_token: Repo.preload(new_rt, [:application, :user])}
  end

  defp create_access_token(%RefreshToken{} = refresh_token) do
    %AccessToken{}
    |> AccessToken.changeset(%{
      application_id: refresh_token.application_id,
      user_id: refresh_token.user_id,
      scopes: refresh_token.scopes
    })
    |> Repo.insert!()
    |> Repo.preload([:application, :user])
  end

  # Handles the case where a token could not be claimed because it was already
  # revoked.
  #
  # Re-fetches the row and inspects `revoke_reason`:
  #   * `"rotated"` — this token was consumed by a legitimate rotation and is now
  #     being *replayed*. That is token theft, so the whole family is revoked. The
  #     audit event is built here (while the preloaded row is in memory) but
  #     logged OUTSIDE the transaction by `exchange_refresh_token/2`, so a failed
  #     audit insert can never roll back the committed family revocation.
  #   * anything else (`"manual"`, `"password_change"`, `nil`, …) — the token was
  #     deliberately revoked, so a retry is a benign (if stale) client request,
  #     not theft. No family is revoked and no theft event is raised.
  defp handle_refresh_token_reuse(%RefreshToken{} = refresh_token, now) do
    current =
      Repo.get(refresh_token.__struct__, refresh_token.id) |> Repo.preload([:application, :user])

    case current do
      nil ->
        # Row vanished between claim and fetch; treat as invalid, not theft.
        %{kind: :invalid}

      _ ->
        if current.revoke_reason == "rotated" do
          family_id = current.token_family_id
          revoked_count = revoke_token_family(family_id, now)
          event = reuse_event_attrs(current, family_id, revoked_count)
          %{kind: :reuse, event: event}
        else
          %{kind: :invalid}
        end
    end
  end

  # Revokes every still-active token in `family_id`.
  #
  # Returns the number of newly revoked tokens. The conditional UPDATE is the same
  # primitive used for claim/`revoke_all_tokens_for_user/1`; the first caller to
  # run it against a family wins the active members, later callers see `0`, which
  # keeps a single audit event per detected reuse even under a concurrent race.
  defp revoke_token_family(nil, _now), do: 0

  defp revoke_token_family(family_id, now) do
    {revoked, _} =
      Repo.update_all(
        from(rt in RefreshToken,
          where: rt.token_family_id == ^family_id and is_nil(rt.revoked_at)
        ),
        set: [revoked_at: now, revoke_reason: "family_reuse"]
      )

    revoked
  end

  # Builds the audit event attributes for a detected refresh-token reuse.
  defp reuse_event_attrs(current, family_id, revoked_count) when is_map(current) do
    application = current.application

    %{
      organization_id: application && application.organization_id,
      actor_type: "application",
      actor_id: current.application_id,
      actor_name: application && application.name,
      resource_type: "oauth_refresh_token",
      resource_id: current.id,
      outcome: "failure",
      metadata: %{
        token_family_id: family_id,
        revoked_token_id: current.id,
        revoked_count: revoked_count,
        client_id: application && application.client_id,
        scopes: current.scopes,
        user_id: current.user_id
      }
    }
  end

  # Maps a rotation transaction outcome to the public `exchange_refresh_token/2`
  # result.
  # A failed rotation transaction: map to a graceful error instead of raising.
  defp map_exchange_result({:error, _} = error), do: error
  defp map_exchange_result({:ok, %{kind: :reuse}}), do: {:error, :refresh_token_reuse_detected}
  defp map_exchange_result({:ok, %{kind: :invalid}}), do: {:error, :invalid_refresh_token}
  defp map_exchange_result({:ok, result}), do: {:ok, result}

  @doc """
  Revokes a refresh token.
  """
  def revoke_refresh_token(%RefreshToken{} = refresh_token) do
    refresh_token
    |> Ecto.Changeset.change()
    |> RefreshToken.revoke("manual")
    |> Repo.update()
  end

  # User Grants - Persistent Consent Tracking

  @doc """
  Creates or updates a user grant for an application.

  If a grant already exists, updates its scopes and un-revokes it if necessary.
  If no grant exists, creates a new one.

  ## Examples

      iex> create_or_update_user_grant(user, application, ["openid", "profile"])
      {:ok, %UserGrant{}}

      iex> create_or_update_user_grant(user, application, "openid profile email")
      {:ok, %UserGrant{}}
  """
  def create_or_update_user_grant(%User{} = user, %Application{} = application, scopes) do
    scopes_string = normalize_scopes(scopes)

    case get_user_grant_including_revoked(user, application) do
      nil ->
        %UserGrant{}
        |> UserGrant.changeset(%{
          user_id: user.id,
          application_id: application.id,
          scopes: scopes_string
        })
        |> Repo.insert()

      existing_grant ->
        existing_grant
        |> UserGrant.changeset(%{scopes: scopes_string, revoked_at: nil})
        |> Repo.update()
    end
  end

  @doc """
  Gets an active (non-revoked) user grant for a user and application.

  Returns nil if no active grant exists or if the grant has been revoked.

  ## Examples

      iex> get_user_grant(user, application)
      %UserGrant{}

      iex> get_user_grant(user, application)
      nil
  """
  def get_user_grant(%User{id: user_id}, %Application{id: app_id}) do
    UserGrant
    |> where([ug], ug.user_id == ^user_id and ug.application_id == ^app_id)
    |> where([ug], is_nil(ug.revoked_at))
    |> Repo.one()
    |> case do
      nil -> nil
      grant -> Repo.preload(grant, [:user, :application])
    end
  end

  @doc """
  Gets a user grant by ID.

  Useful for looking up grants when you have the grant ID (e.g., from a URL parameter).

  ## Examples

      iex> get_user_grant!(123, user)
      %UserGrant{}
  """
  def get_user_grant!(grant_id, %User{id: user_id}) do
    UserGrant
    |> where([ug], ug.id == ^grant_id and ug.user_id == ^user_id)
    |> Repo.one!()
    |> Repo.preload([:user, :application])
  end

  def get_user_grant!(grant_id, %Organization{id: org_id}) do
    UserGrant
    |> join(:inner, [ug], u in User, on: ug.user_id == u.id)
    |> where([ug, u], ug.id == ^grant_id and u.organization_id == ^org_id)
    |> Repo.one!()
    |> Repo.preload([:user, :application])
  end

  @doc """
  Lists all active grants for a user.

  Returns grants ordered by most recently updated first.

  ## Examples

      iex> list_user_grants(user)
      [%UserGrant{}, ...]
  """
  def list_user_grants(%User{id: user_id}) do
    UserGrant
    |> where([ug], ug.user_id == ^user_id)
    |> where([ug], is_nil(ug.revoked_at))
    |> order_by([ug], desc: ug.updated_at)
    |> Repo.all()
    |> Repo.preload([:application])
  end

  @doc """
  Validates that a user has granted sufficient scopes for the request.

  Returns:
  - `{:ok, grant}` if valid grant exists with all requested scopes
  - `{:error, :insufficient_grant}` if grant exists but doesn't cover all scopes
  - `{:error, :no_grant}` if no grant exists

  ## Examples

      iex> validate_user_grant(user, app, ["openid", "profile"])
      {:ok, %UserGrant{}}

      iex> validate_user_grant(user, app, ["openid", "profile", "email"])
      {:error, :insufficient_grant}
  """
  def validate_user_grant(%User{} = user, %Application{} = app, requested_scopes) do
    case get_user_grant(user, app) do
      nil ->
        {:error, :no_grant}

      grant ->
        if UserGrant.scopes_match?(grant, requested_scopes) do
          {:ok, grant}
        else
          {:error, :insufficient_grant}
        end
    end
  end

  @doc """
  Revokes a user grant.

  This marks the grant as revoked but does not delete it, maintaining an audit trail.

  ## Examples

      iex> revoke_user_grant(grant)
      {:ok, %UserGrant{}}
  """
  def revoke_user_grant(%UserGrant{} = grant) do
    grant
    |> Ecto.Changeset.change()
    |> UserGrant.revoke()
    |> Repo.update()
  end

  @doc """
  Revokes all of a user's OAuth credentials in a single pass.

  Marks every outstanding access token, refresh token, and user grant for the
  user as revoked, so that any bearer tokens or consents issued to the account
  can no longer be used. This is intended to be run when a user's password is
  changed or reset, since a compromised password would otherwise keep those
  credentials usable until their natural expiry.

  Unlike `revoke_access_token/1`, `revoke_refresh_token/1`, and
  `revoke_user_grant/1`, this performs bulk updates and does not load each
  record individually. It returns the number of rows revoked for each type.
  """
  def revoke_all_tokens_for_user(%User{id: user_id}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    {access_tokens, _} =
      Repo.update_all(
        from(at in AccessToken,
          where: at.user_id == ^user_id and is_nil(at.revoked_at)
        ),
        set: [revoked_at: now]
      )

    {refresh_tokens, _} =
      Repo.update_all(
        from(rt in RefreshToken,
          where: rt.user_id == ^user_id and is_nil(rt.revoked_at)
        ),
        set: [revoked_at: now, revoke_reason: "password_change"]
      )

    {user_grants, _} =
      Repo.update_all(
        from(ug in UserGrant,
          where: ug.user_id == ^user_id and is_nil(ug.revoked_at)
        ),
        set: [revoked_at: now]
      )

    {:ok,
     %{access_tokens: access_tokens, refresh_tokens: refresh_tokens, user_grants: user_grants}}
  end

  # Private helper to normalize scopes to a space-separated string
  defp normalize_scopes(scopes) when is_list(scopes), do: Enum.join(scopes, " ")
  defp normalize_scopes(scopes) when is_binary(scopes), do: scopes

  # Private helper to get grant regardless of revocation status
  defp get_user_grant_including_revoked(%User{id: user_id}, %Application{id: app_id}) do
    UserGrant
    |> where([ug], ug.user_id == ^user_id and ug.application_id == ^app_id)
    |> Repo.one()
  end
end
