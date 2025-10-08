defmodule AuthifyWeb.AppLinkController do
  use AuthifyWeb, :controller

  alias Authify.Accounts
  alias Authify.OAuth
  alias Authify.SAML

  @doc """
  Proxy endpoint that validates user permissions before redirecting to OAuth2 app.
  """
  def oauth2(conn, %{"app_id" => app_id}) do
    user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    with {app_id, ""} <- Integer.parse(app_id),
         {:ok, app} <- safe_get_oauth_application(app_id, organization),
         true <- user_has_access_to_app?(user, organization, app_id, "oauth2") do
      # Generate OAuth authorization URL
      redirect_uri = List.first(OAuth.Application.redirect_uris_list(app))
      state = generate_state_token()

      auth_url =
        "/#{organization.slug}/oauth/authorize?" <>
          URI.encode_query(%{
            "client_id" => app.client_id,
            "response_type" => "code",
            "scope" => "openid profile email",
            "redirect_uri" => redirect_uri,
            "state" => state
          })

      redirect(conn, to: auth_url)
    else
      _ ->
        conn
        |> put_flash(:error, "Access denied or application not found.")
        |> redirect(to: ~p"/#{organization.slug}/user/dashboard")
    end
  end

  @doc """
  Proxy endpoint that validates user permissions before redirecting to SAML SSO.
  """
  def saml(conn, %{"sp_id" => sp_id}) do
    user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    with {sp_id, ""} <- Integer.parse(sp_id),
         {:ok, _sp} <- safe_get_saml_service_provider(sp_id, organization),
         true <- user_has_access_to_app?(user, organization, sp_id, "saml") do
      # IdP-initiated SSO: redirect to SAML SSO endpoint with sp_id parameter
      redirect(conn, to: ~p"/#{organization.slug}/saml/sso?sp_id=#{sp_id}")
    else
      _ ->
        conn
        |> put_flash(:error, "Access denied or service provider not found.")
        |> redirect(to: ~p"/#{organization.slug}/user/dashboard")
    end
  end

  defp user_has_access_to_app?(user, organization, app_id, app_type) do
    accessible_apps = Accounts.get_user_accessible_applications(user, organization)

    case app_type do
      "oauth2" ->
        Enum.any?(accessible_apps.oauth2_applications, &(&1.id == app_id))

      "saml" ->
        Enum.any?(accessible_apps.saml_service_providers, &(&1.id == app_id))
    end
  end

  defp generate_state_token do
    :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)
  end

  defp safe_get_oauth_application(app_id, organization) do
    {:ok, OAuth.get_application!(app_id, organization)}
  rescue
    Ecto.NoResultsError -> {:error, :not_found}
  end

  defp safe_get_saml_service_provider(sp_id, organization) do
    {:ok, SAML.get_service_provider!(sp_id, organization)}
  rescue
    Ecto.NoResultsError -> {:error, :not_found}
  end
end
