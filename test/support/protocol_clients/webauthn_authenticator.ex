defmodule AuthifyTest.WebAuthnAuthenticator do
  @moduledoc false

  @endpoint AuthifyWeb.Endpoint

  import Plug.Conn, only: [put_session: 3]
  import Phoenix.ConnTest
  import AuthifyWeb.ConnCase, only: [log_in_user: 2]

  defstruct [:private_key, :public_key_raw, :credential_id, :sign_count, :aaguid, :user_verified]

  def new(opts \\ []) do
    {public_key_raw, private_key} = :crypto.generate_key(:ecdh, :prime256v1)

    %__MODULE__{
      private_key: private_key,
      public_key_raw: public_key_raw,
      credential_id: :crypto.strong_rand_bytes(16),
      sign_count: 0,
      aaguid: Keyword.get(opts, :aaguid, <<0::128>>),
      user_verified: Keyword.get(opts, :user_verified, true)
    }
  end

  def create_credential(%__MODULE__{} = authenticator, options) do
    rp_id = options["rp"]["id"]
    challenge = options["challenge"]

    client_data_json_bytes = build_client_data_json("webauthn.create", challenge, rp_id)
    auth_data_bytes = build_reg_auth_data(authenticator, rp_id)

    attestation_object_bytes =
      CBOR.encode(%{
        "fmt" => "none",
        "attStmt" => %{},
        "authData" => %CBOR.Tag{tag: :bytes, value: auth_data_bytes}
      })

    credential_id_b64 = Base.url_encode64(authenticator.credential_id, padding: false)

    credential = %{
      "id" => credential_id_b64,
      "rawId" => credential_id_b64,
      "type" => "public-key",
      "response" => %{
        "clientDataJSON" => Base.url_encode64(client_data_json_bytes, padding: false),
        "attestationObject" => Base.url_encode64(attestation_object_bytes, padding: false)
      }
    }

    {:ok, {credential, authenticator}}
  end

  def sign_challenge(%__MODULE__{} = authenticator, options) do
    rp_id = options["rpId"]
    challenge = options["challenge"]
    new_sign_count = authenticator.sign_count + 1

    client_data_json_bytes = build_client_data_json("webauthn.get", challenge, rp_id)
    auth_data_bytes = build_auth_auth_data(authenticator, rp_id, new_sign_count)

    client_data_hash = :crypto.hash(:sha256, client_data_json_bytes)
    verification_data = auth_data_bytes <> client_data_hash

    signature =
      :crypto.sign(:ecdsa, :sha256, verification_data, [
        authenticator.private_key,
        :prime256v1
      ])

    credential_id_b64 = Base.url_encode64(authenticator.credential_id, padding: false)

    assertion = %{
      "id" => credential_id_b64,
      "rawId" => credential_id_b64,
      "type" => "public-key",
      "response" => %{
        "clientDataJSON" => Base.url_encode64(client_data_json_bytes, padding: false),
        "authenticatorData" => Base.url_encode64(auth_data_bytes, padding: false),
        "signature" => Base.url_encode64(signature, padding: false),
        "userHandle" => nil
      }
    }

    {:ok, {assertion, %{authenticator | sign_count: new_sign_count}}}
  end

  def fetch_registration_options(_conn, user, org) do
    resp =
      build_conn()
      |> log_in_user(user)
      |> put_session(:current_organization_id, org.id)
      |> post("/#{org.slug}/profile/webauthn/register/begin", %{})

    case resp.status do
      200 ->
        body = Jason.decode!(resp.resp_body)
        {:ok, {body["options"], resp}}

      status ->
        {:error, {:begin_failed, status, Jason.decode!(resp.resp_body)}}
    end
  end

  def fetch_authentication_options(conn, _org) do
    resp = post(conn, "/mfa/webauthn/authenticate/begin")

    case resp.status do
      200 ->
        body = Jason.decode!(resp.resp_body)

        case body do
          %{"success" => true, "options" => options} -> {:ok, {options, resp}}
          %{"success" => false, "error" => error} -> {:error, error}
        end

      status ->
        {:error, {:begin_failed, status}}
    end
  end

  defp build_client_data_json(type, challenge, rp_id) do
    Jason.encode!(%{
      "type" => type,
      "challenge" => challenge,
      "origin" => "https://#{rp_id}"
    })
  end

  defp build_reg_auth_data(%__MODULE__{} = authenticator, rp_id) do
    rp_id_hash = :crypto.hash(:sha256, rp_id)
    flags = if authenticator.user_verified, do: 0x45, else: 0x41
    <<4, x::binary-size(32), y::binary-size(32)>> = authenticator.public_key_raw
    cose_key_bytes = encode_cose_key(x, y)
    cred_id_len = byte_size(authenticator.credential_id)

    rp_id_hash <>
      <<flags, 0::32>> <>
      authenticator.aaguid <>
      <<cred_id_len::16>> <>
      authenticator.credential_id <>
      cose_key_bytes
  end

  defp build_auth_auth_data(%__MODULE__{} = authenticator, rp_id, sign_count) do
    rp_id_hash = :crypto.hash(:sha256, rp_id)
    flags = if authenticator.user_verified, do: 0x05, else: 0x01
    rp_id_hash <> <<flags, sign_count::32>>
  end

  defp encode_cose_key(x, y) do
    CBOR.encode(%{
      1 => 2,
      3 => -7,
      -1 => 1,
      -2 => %CBOR.Tag{tag: :bytes, value: x},
      -3 => %CBOR.Tag{tag: :bytes, value: y}
    })
  end
end
