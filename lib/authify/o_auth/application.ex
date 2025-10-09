defmodule Authify.OAuth.Application do
  @moduledoc """
  Schema for OAuth2 and OIDC applications. Supports authorization code flow,
  refresh tokens, and client credentials. Includes PKCE support for public
  clients (SPAs and native apps) and configurable scopes.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias Authify.Accounts.Scope

  @derive {Jason.Encoder,
           except: [
             :organization,
             :authorization_codes,
             :access_tokens,
             :refresh_tokens,
             :scopes,
             :__meta__
           ]}

  schema "applications" do
    field :name, :string
    field :client_id, :string
    field :client_secret, Authify.Encrypted.Binary
    field :redirect_uris, :string
    field :description, :string
    field :is_active, :boolean, default: true
    field :application_type, :string, default: "oauth2_app"
    # Grant types: authorization_code, refresh_token, client_credentials
    field :grant_types, :string, default: "authorization_code refresh_token"
    # Client type: confidential (web), public (spa, native)
    field :client_type, :string, default: "confidential"
    # Require PKCE for this application
    field :require_pkce, :boolean, default: false

    belongs_to :organization, Authify.Accounts.Organization
    has_many :authorization_codes, Authify.OAuth.AuthorizationCode
    has_many :access_tokens, Authify.OAuth.AccessToken
    has_many :refresh_tokens, Authify.OAuth.RefreshToken

    has_many :scopes, Scope,
      foreign_key: :scopeable_id,
      where: [scopeable_type: "Application"],
      on_replace: :delete

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(application, attrs) do
    application
    |> cast(attrs, [
      :name,
      :client_id,
      :client_secret,
      :redirect_uris,
      :description,
      :is_active,
      :application_type,
      :grant_types,
      :client_type,
      :require_pkce,
      :organization_id
    ])
    |> validate_required([:name, :organization_id])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_inclusion(:application_type, ["oauth2_app", "management_api_app"])
    |> validate_inclusion(:client_type, ["confidential", "public"])
    |> validate_redirect_uris()
    |> validate_grant_types()
    |> validate_application_type_requirements(attrs)
    |> enforce_public_client_pkce()
    |> put_client_credentials()
    |> unique_constraint(:client_id)
  end

  @doc false
  def update_changeset(application, attrs) do
    application
    |> cast(attrs, [
      :name,
      :redirect_uris,
      :description,
      :is_active,
      :client_type,
      :grant_types,
      :require_pkce
    ])
    |> validate_required([:name, :redirect_uris])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_inclusion(:client_type, ["confidential", "public"])
    |> validate_redirect_uris()
    |> validate_grant_types()
    |> put_scopes_for_update(application, attrs)
    |> enforce_public_client_pkce()
  end

  @doc false
  def form_changeset(application, attrs \\ %{}) do
    application
    |> cast(attrs, [
      :name,
      :redirect_uris,
      :description,
      :is_active,
      :client_type,
      :grant_types,
      :require_pkce,
      :organization_id
    ])
  end

  defp put_client_credentials(%Ecto.Changeset{valid?: true} = changeset) do
    changeset
    |> put_change(:client_id, generate_client_id())
    |> put_change(:client_secret, generate_client_secret())
  end

  defp put_client_credentials(changeset), do: changeset

  defp validate_redirect_uris(changeset) do
    case get_field(changeset, :redirect_uris) do
      nil ->
        changeset

      uris_string ->
        uris =
          String.split(uris_string, "\n") |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == ""))

        if Enum.all?(uris, &valid_uri?/1) do
          changeset
        else
          add_error(changeset, :redirect_uris, "contains invalid URIs")
        end
    end
  end

  defp validate_grant_types(changeset) do
    case get_field(changeset, :grant_types) do
      nil ->
        changeset

      grant_types_string ->
        grant_types = String.split(grant_types_string, " ") |> Enum.reject(&(&1 == ""))
        valid_grants = ["authorization_code", "refresh_token", "client_credentials"]

        if Enum.all?(grant_types, &(&1 in valid_grants)) do
          changeset
        else
          add_error(changeset, :grant_types, "contains invalid grant types")
        end
    end
  end

  defp enforce_public_client_pkce(changeset) do
    client_type = get_field(changeset, :client_type)

    if client_type == "public" do
      # Public clients MUST use PKCE
      put_change(changeset, :require_pkce, true)
    else
      changeset
    end
  end

  defp validate_application_type_requirements(changeset, attrs) do
    case get_field(changeset, :application_type) do
      "management_api_app" ->
        # Management API apps don't need redirect URIs, but need specific scopes
        changeset
        |> put_scopes_for_create(attrs, :management_api)
        |> maybe_clear_redirect_uris_requirement()

      "oauth2_app" ->
        # OAuth2 apps need redirect URIs and standard OAuth scopes
        changeset
        |> validate_required([:redirect_uris])
        |> put_scopes_for_create(attrs, :oauth)

      _ ->
        changeset
        |> put_scopes_for_create(attrs, :oauth)
    end
  end

  defp put_scopes_for_create(changeset, attrs, scope_type) do
    scopes = get_scopes_from_attrs(attrs)

    if scopes == [] do
      # Set defaults based on application type
      default_scopes =
        case scope_type do
          :oauth -> ["openid", "profile", "email"]
          :management_api -> []
        end

      put_scope_assoc(changeset, default_scopes)
    else
      # Validate scopes based on application type
      valid_scopes =
        case scope_type do
          :oauth -> Authify.Scopes.oauth_scopes() ++ Authify.Scopes.management_api_scopes()
          :management_api -> Authify.Scopes.management_api_scopes()
        end

      invalid_scopes = Enum.reject(scopes, &(&1 in valid_scopes))

      if invalid_scopes != [] do
        add_error(
          changeset,
          :scopes,
          "contains invalid scopes: #{Enum.join(invalid_scopes, ", ")}"
        )
      else
        put_scope_assoc(changeset, scopes)
      end
    end
  end

  defp put_scopes_for_update(changeset, application, attrs) do
    scopes = get_scopes_from_attrs(attrs)

    if scopes == [] do
      # Keep existing scopes if none provided
      changeset
    else
      # Validate scopes based on application type
      valid_scopes =
        case application.application_type do
          "oauth2_app" -> Authify.Scopes.oauth_scopes() ++ Authify.Scopes.management_api_scopes()
          "management_api_app" -> Authify.Scopes.management_api_scopes()
          _ -> Authify.Scopes.oauth_scopes() ++ Authify.Scopes.management_api_scopes()
        end

      invalid_scopes = Enum.reject(scopes, &(&1 in valid_scopes))

      if invalid_scopes != [] do
        add_error(
          changeset,
          :scopes,
          "contains invalid scopes: #{Enum.join(invalid_scopes, ", ")}"
        )
      else
        put_scope_assoc(changeset, scopes)
      end
    end
  end

  defp put_scope_assoc(changeset, scopes) do
    scope_structs =
      Enum.map(scopes, fn scope ->
        %Scope{
          scope: scope,
          scopeable_type: "Application"
        }
      end)

    put_assoc(changeset, :scopes, scope_structs)
  end

  defp get_scopes_from_attrs(attrs) do
    cond do
      # List of scopes from form checkboxes
      is_list(attrs["scopes"]) ->
        attrs["scopes"] |> Enum.reject(&(&1 == ""))

      # Space-separated string (API or legacy)
      is_binary(attrs["scopes"]) ->
        attrs["scopes"] |> String.split(" ") |> Enum.reject(&(&1 == ""))

      # Atom key (list)
      is_list(attrs[:scopes]) ->
        attrs[:scopes] |> Enum.reject(&(&1 == ""))

      # Atom key (string)
      is_binary(attrs[:scopes]) ->
        attrs[:scopes] |> String.split(" ") |> Enum.reject(&(&1 == ""))

      true ->
        []
    end
  end

  defp maybe_clear_redirect_uris_requirement(changeset) do
    # For Management API apps, redirect_uris is not required
    # Set a default value if not provided
    case get_field(changeset, :redirect_uris) do
      nil -> put_change(changeset, :redirect_uris, "")
      "" -> changeset
      _ -> changeset
    end
  end

  defp valid_uri?(uri) do
    case URI.parse(uri) do
      %URI{scheme: scheme, host: host} when scheme in ["http", "https"] and not is_nil(host) ->
        true

      _ ->
        false
    end
  end

  defp generate_client_id do
    :crypto.strong_rand_bytes(16) |> Base.hex_encode32(case: :lower)
  end

  defp generate_client_secret do
    :crypto.strong_rand_bytes(32) |> Base.hex_encode32(case: :lower)
  end

  def redirect_uris_list(%__MODULE__{redirect_uris: uris}) when is_binary(uris) do
    String.split(uris, "\n") |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == ""))
  end

  def redirect_uris_list(_), do: []

  def scopes_list(%__MODULE__{} = application) do
    if Ecto.assoc_loaded?(application.scopes) do
      Enum.map(application.scopes, & &1.scope)
    else
      # Default to OAuth scopes if not loaded
      ["openid", "profile", "email"]
    end
  end

  @doc """
  Returns the list of supported grant types for this application.
  """
  def grant_types_list(%__MODULE__{grant_types: grant_types}) when is_binary(grant_types) do
    String.split(grant_types, " ") |> Enum.reject(&(&1 == ""))
  end

  def grant_types_list(_), do: ["authorization_code", "refresh_token"]

  @doc """
  Checks if the application supports a specific grant type.
  """
  def supports_grant_type?(%__MODULE__{} = app, grant_type) do
    grant_type in grant_types_list(app)
  end

  @doc """
  Checks if the application is a public client (SPA or Native).
  """
  def public_client?(%__MODULE__{client_type: "public"}), do: true
  def public_client?(_), do: false

  @doc """
  Checks if PKCE is required for this application.
  """
  def requires_pkce?(%__MODULE__{require_pkce: true}), do: true
  def requires_pkce?(%__MODULE__{client_type: "public"}), do: true
  def requires_pkce?(_), do: false
end
