defmodule AuthifyWeb.Auth.APIAuth do
  @moduledoc """
  Authentication and authorization for Management API.

  Supports multiple authentication methods:
  - Bearer tokens (OAuth access tokens)
  - API keys (for service accounts)
  - Session-based auth (for web app integration)
  """

  import Plug.Conn
  import Phoenix.Controller

  alias Authify.Guardian

  def init(opts), do: opts

  def call(conn, opts) do
    required_scopes = opts[:require_scopes] || []

    # In test environment, check if API auth is already set up
    if Mix.env() == :test && conn.assigns[:api_authenticated] do
      conn
    else
      case authenticate_request(conn) do
        {:ok, user, organization, scopes} ->
          conn =
            conn
            |> assign(:current_user, user)
            |> assign(:current_organization, organization)
            |> assign(:current_scopes, scopes || [])
            |> assign(:api_authenticated, true)

          # Check if required scopes are present
          if required_scopes == [] or has_required_scopes?(scopes, required_scopes) do
            conn
          else
            conn
            |> put_status(:forbidden)
            |> json(%{
              error: %{
                type: "insufficient_scope",
                message: "Insufficient scope to access this resource",
                details: %{
                  required: required_scopes,
                  provided: scopes || []
                }
              },
              links: %{
                documentation: "/developers/scopes"
              }
            })
            |> halt()
          end

        {:error, reason} ->
          conn
          |> put_status(:unauthorized)
          |> json(%{
            error: %{
              type: "authentication_required",
              message: "Authentication required to access this resource",
              details: reason
            },
            links: %{
              documentation: "/developers/authentication"
            }
          })
          |> halt()
      end
    end
  end

  defp authenticate_request(conn) do
    # Get the organization from the URL (set by OrganizationPlug)
    url_organization = conn.assigns[:current_organization]

    cond do
      # Try Bearer token authentication first
      bearer_token = get_bearer_token(conn) ->
        case authenticate_bearer_token(bearer_token) do
          {:ok, user, token_organization, scopes} ->
            # Validate token's organization matches URL organization
            if url_organization && token_organization.id == url_organization.id do
              {:ok, user, token_organization, scopes}
            else
              {:error, "Token organization mismatch"}
            end

          error ->
            error
        end

      # Fall back to session authentication for web app integration
      Guardian.Plug.current_resource(conn) ->
        user = Guardian.Plug.current_resource(conn)
        organization = url_organization

        if user && organization do
          # Session authentication grants all management API scopes
          all_scopes = [
            "management_app:read",
            "management_app:write",
            "users:read",
            "users:write",
            "invitations:read",
            "invitations:write",
            "applications:read",
            "applications:write",
            "application_groups:read",
            "application_groups:write",
            "saml:read",
            "saml:write",
            "certificates:read",
            "certificates:write",
            "organizations:read",
            "organizations:write"
          ]

          {:ok, user, organization, all_scopes}
        else
          {:error, "Invalid session state"}
        end

      true ->
        {:error, "No authentication provided"}
    end
  end

  defp get_bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] -> token
      _ -> nil
    end
  end

  defp authenticate_bearer_token(token) do
    # Try Personal Access Token first (they have 'authify_pat_' prefix)
    if String.starts_with?(token, "authify_pat_") do
      case authenticate_personal_access_token(token) do
        {:ok, pat} ->
          {:ok, pat.user, pat.organization,
           Authify.Accounts.PersonalAccessToken.scopes_list(pat)}

        {:error, _reason} ->
          {:error, "Invalid or expired personal access token"}
      end
    else
      # Try OAuth access token
      case validate_oauth_access_token(token) do
        {:ok, user, organization, scopes} ->
          {:ok, user, organization, scopes}

        {:error, _oauth_error} ->
          # Fall back to Guardian JWT validation
          case Guardian.decode_and_verify(token) do
            {:ok, %{"sub" => user_id, "org" => org_id}} ->
              user = Authify.Accounts.get_user!(user_id)
              organization = Authify.Accounts.get_organization!(org_id)

              # Guardian JWT gets all management API scopes
              all_scopes = [
                "management_app:read",
                "management_app:write",
                "users:read",
                "users:write",
                "invitations:read",
                "invitations:write",
                "applications:read",
                "applications:write",
                "application_groups:read",
                "application_groups:write",
                "saml:read",
                "saml:write",
                "certificates:read",
                "certificates:write",
                "organizations:read",
                "organizations:write"
              ]

              {:ok, user, organization, all_scopes}

            {:error, _reason} ->
              {:error, "Invalid or expired token"}
          end
      end
    end
  rescue
    _ ->
      {:error, "Invalid token format"}
  end

  defp authenticate_personal_access_token(token) do
    Authify.Accounts.authenticate_personal_access_token(token)
  end

  defp validate_oauth_access_token(token) do
    case Authify.OAuth.get_access_token(token) do
      nil ->
        {:error, "Token not found"}

      access_token ->
        # Check if token is expired
        if DateTime.compare(access_token.expires_at, DateTime.utc_now()) == :lt do
          {:error, "Token expired"}
        else
          # Check if token is revoked
          if access_token.revoked_at do
            {:error, "Token revoked"}
          else
            # Load the application and organization
            application = Authify.OAuth.get_application!(access_token.application_id)
            organization = Authify.Accounts.get_organization!(application.organization_id)

            # Parse scopes from the access token
            scopes = String.split(access_token.scopes, " ") |> Enum.reject(&(&1 == ""))

            # For client credentials flow, user_id is nil
            # We'll create a virtual "service account" representation
            if access_token.user_id do
              # User-bound token
              user = Authify.Accounts.get_user!(access_token.user_id)
              {:ok, user, organization, scopes}
            else
              # Service account token - create a virtual user representing the service
              service_user = %{
                id: nil,
                email: "service@#{application.name}",
                first_name: "Service",
                last_name: "Account",
                service_account: true,
                application_id: application.id
              }

              {:ok, service_user, organization, scopes}
            end
          end
        end
    end
  rescue
    _ ->
      {:error, "Database error during token validation"}
  end

  defp has_required_scopes?(user_scopes, required_scopes) do
    required_scopes
    |> Enum.all?(fn required_scope ->
      Enum.any?(user_scopes, fn user_scope ->
        scope_matches?(user_scope, required_scope)
      end)
    end)
  end

  defp scope_matches?(user_scope, required_scope) do
    # Exact match
    # Wildcard write includes read (e.g., "users:write" includes "users:read")
    user_scope == required_scope or
      (String.ends_with?(user_scope, ":write") and
         String.replace_suffix(user_scope, ":write", ":read") == required_scope)
  end
end
