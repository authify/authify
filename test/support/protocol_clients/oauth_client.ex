defmodule AuthifyTest.OAuthClient do
  @moduledoc false

  @endpoint AuthifyWeb.Endpoint

  import Plug.Conn, only: [get_resp_header: 2]
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
