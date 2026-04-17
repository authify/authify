defmodule AuthifyTest.OAuthClient do
  @moduledoc false

  @endpoint AuthifyWeb.Endpoint

  import Plug.Conn, only: [get_resp_header: 2, put_req_header: 3]
  import Phoenix.ConnTest
  import AuthifyWeb.ConnCase, only: [log_in_user: 2]

  defstruct [:conn, :app, :org]

  def new(conn, app, org), do: %__MODULE__{conn: conn, app: app, org: org}

  def generate_pkce do
    verifier = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
    challenge = Base.url_encode64(:crypto.hash(:sha256, verifier), padding: false)
    {verifier, challenge}
  end

  def authorize(%__MODULE__{app: app, org: org}, user, opts \\ []) do
    scopes = Keyword.get(opts, :scopes, ["openid"])
    state = Keyword.get(opts, :state, Base.encode16(:crypto.strong_rand_bytes(8), case: :lower))
    {verifier, challenge} = generate_pkce()
    nonce = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    params = build_authorize_params(app, scopes, state, challenge, nonce)

    auth_conn = log_in_user(build_conn(), user)
    resp = get(auth_conn, "/#{org.slug}/oauth/authorize", params)

    handle_authorize_response(resp, org, user, params, verifier, nonce)
  end

  defp build_authorize_params(app, scopes, state, challenge, nonce) do
    %{
      "client_id" => app.client_id,
      "redirect_uri" => first_redirect_uri(app),
      "response_type" => "code",
      "scope" => Enum.join(scopes, " "),
      "state" => state,
      "code_challenge" => challenge,
      "code_challenge_method" => "S256",
      "nonce" => nonce
    }
  end

  defp handle_authorize_response(%{status: 302} = resp, _org, _user, _params, verifier, nonce) do
    location = resp |> get_resp_header("location") |> List.first()

    case extract_code(location) do
      {:ok, code} -> {:ok, {resp, code, verifier, nonce}}
      err -> err
    end
  end

  defp handle_authorize_response(%{status: 200}, org, user, params, verifier, nonce) do
    consent_conn = log_in_user(build_conn(), user)
    consent_params = Map.put(params, "approve", "true")
    consent_resp = post(consent_conn, "/#{org.slug}/oauth/consent", consent_params)
    location = consent_resp |> get_resp_header("location") |> List.first()

    case extract_code(location) do
      {:ok, code} -> {:ok, {consent_resp, code, verifier, nonce}}
      err -> err
    end
  end

  defp handle_authorize_response(%{status: status}, _org, _user, _params, _verifier, _nonce) do
    {:error, {:unexpected_status, status}}
  end

  def exchange_code(%__MODULE__{app: app, org: org}, _conn, code, verifier) do
    params = %{
      "grant_type" => "authorization_code",
      "client_id" => app.client_id,
      "client_secret" => app.client_secret,
      "code" => code,
      "redirect_uri" => first_redirect_uri(app),
      "code_verifier" => verifier
    }

    resp = post(build_conn(), "/#{org.slug}/oauth/token", params)

    case resp.status do
      200 ->
        body = Jason.decode!(resp.resp_body)
        validate_token_response(body)

      _status ->
        body = Jason.decode!(resp.resp_body)
        {:error, {:token_exchange_failed, body}}
    end
  end

  defp validate_token_response(body) do
    required = ["access_token", "token_type", "expires_in"]
    missing = Enum.reject(required, &Map.has_key?(body, &1))

    cond do
      missing != [] ->
        {:error, {:missing_fields, missing}}

      body["token_type"] != "Bearer" ->
        {:error, {:wrong_token_type, body["token_type"]}}

      true ->
        {:ok,
         %{
           access_token: body["access_token"],
           id_token: body["id_token"],
           refresh_token: body["refresh_token"],
           expires_in: body["expires_in"],
           token_type: body["token_type"]
         }}
    end
  end

  def fetch_userinfo(%__MODULE__{org: org}, access_token) do
    resp =
      build_conn()
      |> put_req_header("authorization", "Bearer #{access_token}")
      |> get("/#{org.slug}/oauth/userinfo")

    case resp.status do
      200 -> {:ok, Jason.decode!(resp.resp_body)}
      _status -> {:error, {:userinfo_failed, resp.status}}
    end
  end

  def refresh(%__MODULE__{app: app, org: org}, refresh_token) do
    params = %{
      "grant_type" => "refresh_token",
      "client_id" => app.client_id,
      "client_secret" => app.client_secret,
      "refresh_token" => refresh_token
    }

    resp = post(build_conn(), "/#{org.slug}/oauth/token", params)

    case resp.status do
      200 ->
        body = Jason.decode!(resp.resp_body)

        if body["access_token"] && body["token_type"] == "Bearer" do
          {:ok,
           %{
             access_token: body["access_token"],
             id_token: body["id_token"],
             refresh_token: body["refresh_token"],
             expires_in: body["expires_in"],
             token_type: body["token_type"]
           }}
        else
          {:error, {:invalid_refresh_response, body}}
        end

      _status ->
        {:error, {:refresh_failed, Jason.decode!(resp.resp_body)}}
    end
  end

  def client_credentials(%__MODULE__{app: app, org: org}, opts \\ []) do
    scopes = Keyword.get(opts, :scopes, [])

    params = %{
      "grant_type" => "client_credentials",
      "client_id" => app.client_id,
      "client_secret" => app.client_secret,
      "scope" => Enum.join(scopes, " ")
    }

    resp = post(build_conn(), "/#{org.slug}/oauth/token", params)

    case resp.status do
      200 ->
        body = Jason.decode!(resp.resp_body)

        if body["access_token"] && body["token_type"] == "Bearer" do
          {:ok,
           %{
             access_token: body["access_token"],
             token_type: body["token_type"],
             expires_in: body["expires_in"]
           }}
        else
          {:error, {:invalid_response, body}}
        end

      _status ->
        {:error, {:client_credentials_failed, Jason.decode!(resp.resp_body)}}
    end
  end

  def validate_id_token(%__MODULE__{app: app, org: org}, id_token, opts \\ []) do
    expected_nonce = Keyword.get(opts, :nonce)

    with {:ok, {header_b64, payload_b64, sig_b64}} <- split_jwt(id_token),
         {:ok, header} <- decode_json_b64(header_b64),
         {:ok, claims} <- decode_json_b64(payload_b64),
         {:ok, signature} <- Base.url_decode64(sig_b64, padding: false),
         {:ok, public_key} <- fetch_signing_key(org, header["kid"]),
         :ok <- verify_signature("#{header_b64}.#{payload_b64}", signature, public_key),
         :ok <- validate_claims(claims, app, org, expected_nonce) do
      {:ok, claims}
    end
  end

  defp split_jwt(token) do
    case String.split(token, ".") do
      [h, p, s] -> {:ok, {h, p, s}}
      _ -> {:error, :invalid_jwt_format}
    end
  end

  defp decode_json_b64(b64) do
    with {:ok, json} <- Base.url_decode64(b64, padding: false),
         {:ok, decoded} <- Jason.decode(json) do
      {:ok, decoded}
    else
      _ -> {:error, :jwt_decode_failed}
    end
  end

  defp fetch_signing_key(org, kid) do
    discovery_resp = get(build_conn(), "/#{org.slug}/.well-known/openid-configuration")
    discovery = Jason.decode!(discovery_resp.resp_body)

    base_url = AuthifyWeb.Endpoint.url()
    jwks_path = String.replace_prefix(discovery["jwks_uri"], base_url, "")

    jwks_resp = get(build_conn(), jwks_path)
    keys = Jason.decode!(jwks_resp.resp_body)["keys"] || []

    key = Enum.find(keys, List.first(keys), &(&1["kid"] == kid))

    if key, do: parse_rsa_public_key(key), else: {:error, :no_signing_key}
  end

  defp parse_rsa_public_key(%{"n" => n_b64, "e" => e_b64}) do
    with {:ok, n_bin} <- Base.url_decode64(n_b64, padding: false),
         {:ok, e_bin} <- Base.url_decode64(e_b64, padding: false) do
      {:ok, {:RSAPublicKey, :binary.decode_unsigned(n_bin), :binary.decode_unsigned(e_bin)}}
    else
      _ -> {:error, :invalid_jwk}
    end
  end

  defp verify_signature(signing_input, signature, public_key) do
    if :public_key.verify(signing_input, :sha256, signature, public_key) do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  defp validate_claims(claims, app, org, expected_nonce) do
    expected_iss = "#{AuthifyWeb.Endpoint.url()}/#{org.slug}"
    now = System.system_time(:second)

    cond do
      claims["iss"] != expected_iss ->
        {:error, :wrong_issuer}

      claims["aud"] != app.client_id ->
        {:error, :wrong_audience}

      is_nil(claims["exp"]) or claims["exp"] <= now ->
        {:error, :expired}

      is_nil(claims["iat"]) ->
        {:error, :missing_iat}

      not is_nil(expected_nonce) and claims["nonce"] != expected_nonce ->
        {:error, :nonce_mismatch}

      true ->
        :ok
    end
  end

  defp first_redirect_uri(app) do
    app.redirect_uris
    |> String.split("\n")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> List.first()
  end

  defp extract_code(url) when is_binary(url) do
    params = url |> URI.parse() |> Map.get(:query, "") |> URI.decode_query()

    case Map.get(params, "code") do
      nil -> {:error, :no_code_in_redirect}
      code -> {:ok, code}
    end
  end

  defp extract_code(_), do: {:error, :no_redirect_url}
end
