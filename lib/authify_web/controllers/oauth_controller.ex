defmodule AuthifyWeb.OAuthController do
  use AuthifyWeb, :controller

  alias Authify.OAuth
  alias Authify.Accounts

  @doc """
  OAuth2 Authorization endpoint.
  Displays consent screen and handles user authorization.
  Supports PKCE (code_challenge and code_challenge_method parameters).
  """
  def authorize(conn, params) do
    organization = conn.assigns.current_organization

    with {:ok, application} <- validate_client_id(params["client_id"], organization),
         {:ok, redirect_uri} <- validate_redirect_uri(application, params["redirect_uri"]),
         {:ok, scopes} <- validate_scopes(application, params["scope"]),
         :ok <- validate_response_type(params["response_type"]),
         :ok <- validate_pkce_for_application(application, params) do
      if Authify.Guardian.Plug.current_resource(conn) do
        # User is already authenticated, show consent screen
        # Pass PKCE params through to consent
        render_consent_screen(conn, application, redirect_uri, scopes, params)
      else
        # User not authenticated, redirect to login with return URL
        login_url =
          "/login?" <>
            URI.encode_query(%{
              "return_to" => current_url(conn)
            })

        redirect(conn, to: login_url)
      end
    else
      {:error, error} ->
        render_error(conn, error, params["redirect_uri"], params["state"])
    end
  end

  @doc """
  User consent handling - approve or deny authorization.
  Includes PKCE parameters when creating authorization code.
  """
  def consent(conn, %{"approve" => "true"} = params) do
    user = Authify.Guardian.Plug.current_resource(conn)
    organization = conn.assigns.current_organization

    with {:ok, application} <- validate_client_id(params["client_id"], organization),
         {:ok, redirect_uri} <- validate_redirect_uri(application, params["redirect_uri"]),
         {:ok, scopes} <- validate_scopes(application, params["scope"]) do
      # Extract PKCE parameters if present
      pkce_params = extract_pkce_params(params)

      case OAuth.create_authorization_code(application, user, redirect_uri, scopes, pkce_params) do
        {:ok, auth_code} ->
          query_params = %{"code" => auth_code.code}

          query_params =
            if params["state"],
              do: Map.put(query_params, "state", params["state"]),
              else: query_params

          redirect_url = redirect_uri <> "?" <> URI.encode_query(query_params)
          redirect(conn, external: redirect_url)

        {:error, :organization_mismatch} ->
          render_error(conn, "invalid_request", params["redirect_uri"], params["state"])

        {:error, _changeset} ->
          render_error(conn, "server_error", params["redirect_uri"], params["state"])
      end
    else
      {:error, error} ->
        render_error(conn, error, params["redirect_uri"], params["state"])
    end
  end

  def consent(conn, %{"approve" => "false"} = params) do
    # User denied authorization
    if params["redirect_uri"] do
      query_params = %{"error" => "access_denied"}

      query_params =
        if params["state"],
          do: Map.put(query_params, "state", params["state"]),
          else: query_params

      redirect_url = params["redirect_uri"] <> "?" <> URI.encode_query(query_params)
      redirect(conn, external: redirect_url)
    else
      conn
      |> put_flash(:error, "Authorization denied.")
      |> redirect(to: "/#{conn.assigns.current_organization.slug}/dashboard")
    end
  end

  @doc """
  OAuth2 Token endpoint.
  Exchanges authorization code for access token, or refreshes access token.
  Supports grant types: authorization_code, refresh_token, client_credentials.
  """
  def token(conn, params) do
    case params["grant_type"] do
      "authorization_code" ->
        handle_authorization_code_grant(conn, params)

      "refresh_token" ->
        handle_refresh_token_grant(conn, params)

      "client_credentials" ->
        handle_client_credentials_grant(conn, params)

      _ ->
        json(conn, %{
          error: "unsupported_grant_type",
          error_description:
            "Supported grant types: authorization_code, refresh_token, client_credentials"
        })
    end
  end

  @doc """
  OIDC UserInfo endpoint.
  Returns user information based on access token.
  """
  def userinfo(conn, _params) do
    organization = conn.assigns.current_organization

    case get_bearer_token(conn) do
      {:ok, token} ->
        case OAuth.validate_access_token(token, organization) do
          {:ok, access_token} ->
            scopes = OAuth.AccessToken.scopes_list(access_token)
            claims = OAuth.generate_userinfo_claims(access_token.user, scopes)
            json(conn, claims)

          {:error, _} ->
            conn
            |> put_status(:unauthorized)
            |> json(%{error: "invalid_token"})
        end

      {:error, _} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{
          error: "invalid_request",
          error_description: "Missing or invalid authorization header"
        })
    end
  end

  # Private helper functions

  defp validate_client_id(nil, _organization), do: {:error, "invalid_request"}

  defp validate_client_id(client_id, organization) do
    case OAuth.get_application_by_client_id(client_id, organization) do
      nil -> {:error, "invalid_client"}
      application -> {:ok, application}
    end
  end

  defp validate_redirect_uri(application, redirect_uri) do
    if OAuth.valid_redirect_uri?(application, redirect_uri) do
      {:ok, redirect_uri}
    else
      {:error, "invalid_redirect_uri"}
    end
  end

  defp validate_scopes(application, scope_string) do
    scopes = if scope_string, do: String.split(scope_string, " "), else: ["openid"]

    if OAuth.valid_scopes?(application, scopes) do
      {:ok, scopes}
    else
      {:error, "invalid_scope"}
    end
  end

  defp validate_response_type("code"), do: :ok
  defp validate_response_type(_), do: {:error, "unsupported_response_type"}

  defp validate_pkce_for_application(application, params) do
    code_challenge = params["code_challenge"]
    requires_pkce = OAuth.Application.requires_pkce?(application)

    cond do
      # PKCE required but not provided
      requires_pkce && !code_challenge ->
        {:error, "invalid_request"}

      # PKCE provided - validate method
      code_challenge ->
        method = params["code_challenge_method"] || "plain"

        if method in ["S256", "plain"] do
          :ok
        else
          {:error, "invalid_request"}
        end

      # PKCE not required and not provided
      true ->
        :ok
    end
  end

  defp render_consent_screen(conn, application, redirect_uri, scopes, params) do
    render(conn, :consent, %{
      application: application,
      redirect_uri: redirect_uri,
      scopes: scopes,
      state: params["state"],
      code_challenge: params["code_challenge"],
      code_challenge_method: params["code_challenge_method"],
      layout: false
    })
  end

  defp extract_pkce_params(params) do
    %{}
    |> maybe_add_param(:code_challenge, params["code_challenge"])
    |> maybe_add_param(:code_challenge_method, params["code_challenge_method"])
  end

  defp maybe_add_param(map, _key, nil), do: map
  defp maybe_add_param(map, key, value), do: Map.put(map, key, value)

  defp render_error(conn, error, redirect_uri, state) do
    if redirect_uri do
      query_params = %{"error" => error}
      query_params = if state, do: Map.put(query_params, "state", state), else: query_params

      redirect_url = redirect_uri <> "?" <> URI.encode_query(query_params)
      redirect(conn, external: redirect_url)
    else
      conn
      |> put_status(:bad_request)
      |> json(%{error: error})
    end
  end

  defp handle_authorization_code_grant(conn, params) do
    organization = conn.assigns.current_organization

    with {:ok, application} <-
           validate_authorization_code_client(
             params["client_id"],
             params["client_secret"],
             organization
           ),
         {:ok, auth_code} <- get_authorization_code(params["code"]),
         :ok <- verify_pkce(auth_code, params["code_verifier"]),
         {:ok, result} <- OAuth.exchange_authorization_code(auth_code, application) do
      access_token = result.access_token
      refresh_token = result.refresh_token

      response = %{
        access_token: access_token.token,
        token_type: "Bearer",
        expires_in: 3600,
        scope: access_token.scopes
      }

      # Add refresh token if present
      response =
        if refresh_token do
          Map.put(response, :refresh_token, refresh_token.token)
        else
          response
        end

      # Add ID token for OIDC if openid scope is requested
      response =
        if "openid" in OAuth.AccessToken.scopes_list(access_token) do
          id_token = generate_id_token(access_token)
          Map.put(response, :id_token, id_token)
        else
          response
        end

      json(conn, response)
    else
      {:error, :invalid_client} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "invalid_client"})

      {:error, :invalid_grant} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "invalid_grant"})

      {:error, :invalid_authorization_code} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "invalid_grant"})

      {:error, :invalid_pkce} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "invalid_grant", error_description: "PKCE verification failed"})

      {:error, _} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "invalid_request"})
    end
  end

  defp handle_refresh_token_grant(conn, params) do
    organization = conn.assigns.current_organization

    with {:ok, application} <-
           validate_authorization_code_client(
             params["client_id"],
             params["client_secret"],
             organization
           ),
         {:ok, refresh_token} <- get_refresh_token(params["refresh_token"]),
         :ok <- verify_refresh_token_application(refresh_token, application),
         {:ok, result} <- OAuth.exchange_refresh_token(refresh_token) do
      access_token = result.access_token
      new_refresh_token = result.refresh_token

      response = %{
        access_token: access_token.token,
        token_type: "Bearer",
        expires_in: 3600,
        scope: access_token.scopes,
        refresh_token: new_refresh_token.token
      }

      # Add ID token for OIDC if openid scope is requested
      response =
        if "openid" in OAuth.AccessToken.scopes_list(access_token) do
          id_token = generate_id_token(access_token)
          Map.put(response, :id_token, id_token)
        else
          response
        end

      json(conn, response)
    else
      {:error, :invalid_client} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "invalid_client"})

      {:error, :invalid_refresh_token} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "invalid_grant", error_description: "Invalid or expired refresh token"})

      {:error, _} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "invalid_request"})
    end
  end

  defp handle_client_credentials_grant(conn, params) do
    organization = conn.assigns.current_organization

    with {:ok, application} <-
           validate_client_credentials(params["client_id"], params["client_secret"], organization),
         {:ok, scopes} <- validate_requested_scopes(application, params["scope"]) do
      case OAuth.create_management_api_access_token(application, scopes) do
        {:ok, access_token} ->
          response = %{
            access_token: access_token.token,
            token_type: "Bearer",
            expires_in: 3600,
            scope: access_token.scopes
          }

          json(conn, response)

        {:error, :invalid_application_type} ->
          conn
          |> put_status(:bad_request)
          |> json(%{
            error: "invalid_client",
            error_description: "Application is not configured for Management API access"
          })

        {:error, changeset} ->
          # Token creation failed
          conn
          |> put_status(:bad_request)
          |> json(%{error: "invalid_request", details: changeset.errors})
      end
    else
      {:error, :invalid_client} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "invalid_client"})

      {:error, :invalid_application_type} ->
        conn
        |> put_status(:bad_request)
        |> json(%{
          error: "unauthorized_client",
          error_description:
            "This application is not authorized to use the client_credentials grant type"
        })

      {:error, :invalid_scope} ->
        conn
        |> put_status(:bad_request)
        |> json(%{
          error: "invalid_scope",
          error_description: "Invalid scope for Management API access"
        })
    end
  end

  defp validate_client_credentials(client_id, client_secret, organization) do
    case OAuth.get_application_by_client_id(client_id, organization) do
      %{client_secret: ^client_secret, application_type: "management_api_app"} = application ->
        {:ok, application}

      %{client_secret: ^client_secret, application_type: "oauth2_app"} ->
        {:error, :invalid_application_type}

      _ ->
        {:error, :invalid_client}
    end
  end

  defp validate_authorization_code_client(client_id, client_secret, organization) do
    case OAuth.get_application_by_client_id(client_id, organization) do
      %{client_secret: ^client_secret} = application ->
        {:ok, application}

      _ ->
        {:error, :invalid_client}
    end
  end

  defp get_authorization_code(code) do
    case OAuth.get_authorization_code(code) do
      nil -> {:error, :invalid_grant}
      auth_code -> {:ok, auth_code}
    end
  end

  defp generate_id_token(access_token) do
    user = access_token.user
    scopes = OAuth.AccessToken.scopes_list(access_token)

    claims = %{
      "iss" => AuthifyWeb.Endpoint.url(),
      "sub" => to_string(user.id),
      "aud" => access_token.application.client_id,
      "exp" => DateTime.to_unix(access_token.expires_at),
      "iat" => DateTime.to_unix(access_token.inserted_at),
      "auth_time" => DateTime.to_unix(access_token.inserted_at)
    }

    # Add additional claims based on scopes
    claims =
      if "profile" in scopes do
        Map.merge(claims, %{
          "name" => Accounts.User.full_name(user),
          "preferred_username" => user.email
        })
      else
        claims
      end

    claims =
      if "email" in scopes do
        Map.merge(claims, %{
          "email" => user.email,
          "email_verified" => true
        })
      else
        claims
      end

    # For simplicity, return unsigned JWT. In production, this should be signed
    header = %{"alg" => "none", "typ" => "JWT"}

    header_json = Jason.encode!(header)
    claims_json = Jason.encode!(claims)

    Base.url_encode64(header_json, padding: false) <>
      "." <>
      Base.url_encode64(claims_json, padding: false) <> "."
  end

  defp get_bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] -> {:ok, token}
      _ -> {:error, :missing_token}
    end
  end

  defp validate_requested_scopes(application, scope_string) do
    # Get the scopes granted to this application
    application = OAuth.get_application!(application.id)
    granted_scopes = Authify.OAuth.Application.scopes_list(application)

    # Parse requested scopes from the scope parameter
    requested_scopes =
      if scope_string && scope_string != "",
        do: String.split(scope_string, " "),
        else: []

    # If no scopes requested, use ALL granted scopes
    scopes = if Enum.empty?(requested_scopes), do: granted_scopes, else: requested_scopes

    # Validate requested scopes are a subset of granted scopes
    invalid_scopes = scopes -- granted_scopes

    if Enum.empty?(invalid_scopes) do
      {:ok, Enum.join(scopes, " ")}
    else
      {:error, :invalid_scope}
    end
  end

  defp verify_pkce(auth_code, code_verifier) do
    if OAuth.AuthorizationCode.verify_pkce(auth_code, code_verifier) do
      :ok
    else
      {:error, :invalid_pkce}
    end
  end

  defp get_refresh_token(nil), do: {:error, :invalid_refresh_token}

  defp get_refresh_token(token) do
    case OAuth.get_refresh_token(token) do
      nil -> {:error, :invalid_refresh_token}
      refresh_token -> {:ok, refresh_token}
    end
  end

  defp verify_refresh_token_application(refresh_token, application) do
    if refresh_token.application_id == application.id do
      :ok
    else
      {:error, :invalid_refresh_token}
    end
  end
end
