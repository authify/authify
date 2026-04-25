defmodule AuthifyTest.WebAuthnAuthenticatorTest do
  use AuthifyWeb.ConnCase, async: true

  alias AuthifyTest.WebAuthnAuthenticator

  describe "new/1" do
    test "returns a struct with EC P-256 key material" do
      auth = WebAuthnAuthenticator.new()

      assert %WebAuthnAuthenticator{} = auth
      # EC P-256 public key: uncompressed point = 0x04 || 32-byte x || 32-byte y = 65 bytes
      assert <<4, _x::binary-size(32), _y::binary-size(32)>> = auth.public_key_raw
      # P-256 private key is a 32-byte scalar
      assert byte_size(auth.private_key) == 32
    end

    test "starts with sign_count of 0" do
      auth = WebAuthnAuthenticator.new()
      assert auth.sign_count == 0
    end

    test "generates a random 16-byte credential_id" do
      auth = WebAuthnAuthenticator.new()
      assert byte_size(auth.credential_id) == 16
    end

    test "generates unique key material on each call" do
      auth1 = WebAuthnAuthenticator.new()
      auth2 = WebAuthnAuthenticator.new()
      refute auth1.public_key_raw == auth2.public_key_raw
      refute auth1.credential_id == auth2.credential_id
    end

    test "defaults aaguid to 16 zero bytes" do
      auth = WebAuthnAuthenticator.new()
      assert auth.aaguid == <<0::128>>
    end

    test "accepts :user_verified option" do
      auth = WebAuthnAuthenticator.new(user_verified: false)
      assert auth.user_verified == false
    end

    test "defaults user_verified to true" do
      auth = WebAuthnAuthenticator.new()
      assert auth.user_verified == true
    end
  end

  describe "registration authData binary structure" do
    setup do
      auth = WebAuthnAuthenticator.new()
      rp_id = "localhost"

      # Build the authData using the internal helper via create_credential
      options = %{
        "challenge" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
        "rp" => %{"id" => rp_id, "name" => "Test"}
      }

      {:ok, {credential, _auth}} = WebAuthnAuthenticator.create_credential(auth, options)

      attestation_bytes =
        credential["response"]["attestationObject"]
        |> Base.url_decode64!(padding: false)

      {:ok, %{"authData" => auth_data_tag}, ""} = CBOR.decode(attestation_bytes)

      auth_data =
        if is_struct(auth_data_tag, CBOR.Tag), do: auth_data_tag.value, else: auth_data_tag

      %{auth: auth, auth_data: auth_data, rp_id: rp_id}
    end

    test "rpIdHash is SHA-256 of the rpId string (not the full origin)", %{
      auth_data: auth_data,
      rp_id: rp_id
    } do
      <<rp_id_hash::binary-size(32), _rest::binary>> = auth_data
      expected_hash = :crypto.hash(:sha256, rp_id)
      assert rp_id_hash == expected_hash
    end

    test "flags byte has UP(0x01) and AT(0x40) set for user_verified=true", %{
      auth_data: auth_data
    } do
      <<_rp_id_hash::binary-size(32), flags::8, _rest::binary>> = auth_data
      # UP=0x01, UV=0x04, AT=0x40 => 0x45
      assert Bitwise.band(flags, 0x01) != 0, "UP flag must be set"
      assert Bitwise.band(flags, 0x04) != 0, "UV flag must be set for user_verified=true"
      assert Bitwise.band(flags, 0x40) != 0, "AT flag must be set in registration"
    end

    test "flags byte has UP and AT set but UV clear for user_verified=false" do
      auth = WebAuthnAuthenticator.new(user_verified: false)

      options = %{
        "challenge" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
        "rp" => %{"id" => "localhost", "name" => "Test"}
      }

      {:ok, {credential, _auth}} = WebAuthnAuthenticator.create_credential(auth, options)

      auth_data =
        credential["response"]["attestationObject"]
        |> Base.url_decode64!(padding: false)
        |> then(fn bytes ->
          {:ok, %{"authData" => tag}, ""} = CBOR.decode(bytes)
          if is_struct(tag, CBOR.Tag), do: tag.value, else: tag
        end)

      <<_hash::binary-size(32), flags::8, _rest::binary>> = auth_data
      assert Bitwise.band(flags, 0x01) != 0, "UP must be set"
      assert Bitwise.band(flags, 0x04) == 0, "UV must be clear for user_verified=false"
      assert Bitwise.band(flags, 0x40) != 0, "AT must be set"
    end

    test "sign_count is 0 in registration authData", %{auth_data: auth_data} do
      <<_rp_id_hash::binary-size(32), _flags::8, sign_count::32, _rest::binary>> = auth_data
      assert sign_count == 0
    end

    test "aaguid is all zeros at bytes 37-52", %{auth_data: auth_data, auth: auth} do
      <<_rp_id_hash::binary-size(32), _flags::8, _sign_count::32, aaguid::binary-size(16),
        _rest::binary>> = auth_data

      assert aaguid == auth.aaguid
    end

    test "credential_id length and value are correct", %{auth_data: auth_data, auth: auth} do
      <<_rp_id_hash::binary-size(32), _flags::8, _sign_count::32, _aaguid::binary-size(16),
        cred_id_len::16, credential_id::binary-size(cred_id_len), _cose_key::binary>> = auth_data

      assert cred_id_len == byte_size(auth.credential_id)
      assert credential_id == auth.credential_id
    end

    test "COSE public key is valid CBOR with EC2 kty, ES256 alg, P-256 curve", %{
      auth_data: auth_data,
      auth: auth
    } do
      # Extract COSE key bytes (everything after credential data)
      <<_rp_id_hash::binary-size(32), _flags::8, _sign_count::32, _aaguid::binary-size(16),
        cred_id_len::16, _cred_id::binary-size(cred_id_len), cose_key_bytes::binary>> = auth_data

      # Decode using Wax.Utils.CBOR (which unwraps CBOR.Tag byte strings)
      {:ok, cose_key, _} = Wax.Utils.CBOR.decode(cose_key_bytes)

      assert cose_key[1] == 2, "kty must be 2 (EC2)"
      assert cose_key[3] == -7, "alg must be -7 (ES256)"
      assert cose_key[-1] == 1, "crv must be 1 (P-256)"
      assert byte_size(cose_key[-2]) == 32, "x coordinate must be 32 bytes"
      assert byte_size(cose_key[-3]) == 32, "y coordinate must be 32 bytes"

      # Verify x and y match the authenticator's public key
      <<4, expected_x::binary-size(32), expected_y::binary-size(32)>> = auth.public_key_raw
      assert cose_key[-2] == expected_x
      assert cose_key[-3] == expected_y
    end
  end

  describe "create_credential/2" do
    setup do
      auth = WebAuthnAuthenticator.new()
      challenge = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

      options = %{
        "challenge" => challenge,
        "rp" => %{"id" => "localhost", "name" => "Test"}
      }

      {:ok, {credential, returned_auth}} = WebAuthnAuthenticator.create_credential(auth, options)
      %{auth: auth, credential: credential, challenge: challenge, returned_auth: returned_auth}
    end

    test "returns authenticator unchanged (immutable)", %{
      auth: auth,
      returned_auth: returned_auth
    } do
      assert auth.sign_count == returned_auth.sign_count
      assert auth.credential_id == returned_auth.credential_id
      assert auth.public_key_raw == returned_auth.public_key_raw
    end

    test "credential id matches base64url-encoded authenticator credential_id", %{
      auth: auth,
      credential: credential
    } do
      expected = Base.url_encode64(auth.credential_id, padding: false)
      assert credential["id"] == expected
      assert credential["rawId"] == expected
    end

    test "credential type is 'public-key'", %{credential: credential} do
      assert credential["type"] == "public-key"
    end

    test "clientDataJSON decodes to valid JSON with correct type and challenge", %{
      credential: credential,
      challenge: challenge
    } do
      client_data =
        credential["response"]["clientDataJSON"]
        |> Base.url_decode64!(padding: false)
        |> Jason.decode!()

      assert client_data["type"] == "webauthn.create"
      assert client_data["challenge"] == challenge
      assert client_data["origin"] == "https://localhost"
    end

    test "attestationObject decodes to CBOR map with fmt=none and empty attStmt", %{
      credential: credential
    } do
      {:ok, att_obj, ""} =
        credential["response"]["attestationObject"]
        |> Base.url_decode64!(padding: false)
        |> CBOR.decode()

      assert att_obj["fmt"] == "none"
      assert att_obj["attStmt"] == %{}
      # authData is present as a CBOR.Tag byte string
      assert match?(%CBOR.Tag{tag: :bytes}, att_obj["authData"]) or
               is_binary(att_obj["authData"])
    end
  end

  describe "sign_challenge/2" do
    setup do
      auth = WebAuthnAuthenticator.new()
      challenge = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

      options = %{
        "challenge" => challenge,
        "rpId" => "localhost"
      }

      {:ok, {assertion, updated_auth}} = WebAuthnAuthenticator.sign_challenge(auth, options)

      %{
        auth: auth,
        assertion: assertion,
        challenge: challenge,
        updated_auth: updated_auth,
        options: options
      }
    end

    test "returns assertion with correct credential id", %{auth: auth, assertion: assertion} do
      expected = Base.url_encode64(auth.credential_id, padding: false)
      assert assertion["id"] == expected
      assert assertion["rawId"] == expected
    end

    test "returns assertion with type 'public-key'", %{assertion: assertion} do
      assert assertion["type"] == "public-key"
    end

    test "clientDataJSON has type webauthn.get and matches challenge", %{
      assertion: assertion,
      challenge: challenge
    } do
      client_data =
        assertion["response"]["clientDataJSON"]
        |> Base.url_decode64!(padding: false)
        |> Jason.decode!()

      assert client_data["type"] == "webauthn.get"
      assert client_data["challenge"] == challenge
      assert client_data["origin"] == "https://localhost"
    end

    test "authenticatorData has correct rpIdHash and flags at correct offsets", %{
      assertion: assertion
    } do
      auth_data =
        assertion["response"]["authenticatorData"]
        |> Base.url_decode64!(padding: false)

      <<rp_id_hash::binary-size(32), flags::8, sign_count::32>> = auth_data

      expected_hash = :crypto.hash(:sha256, "localhost")
      assert rp_id_hash == expected_hash
      assert Bitwise.band(flags, 0x01) != 0, "UP flag must be set"
      assert Bitwise.band(flags, 0x04) != 0, "UV flag must be set (user_verified=true)"
      assert Bitwise.band(flags, 0x40) == 0, "AT flag must NOT be set in authentication"
      assert sign_count == 1
    end

    test "counter is incremented by 1 in returned authenticator", %{
      auth: auth,
      updated_auth: updated_auth
    } do
      assert updated_auth.sign_count == auth.sign_count + 1
    end

    test "counter increments on each successive call" do
      auth = WebAuthnAuthenticator.new()
      options = %{"challenge" => "abc", "rpId" => "localhost"}

      {:ok, {_a1, auth1}} = WebAuthnAuthenticator.sign_challenge(auth, options)
      {:ok, {_a2, auth2}} = WebAuthnAuthenticator.sign_challenge(auth1, options)
      {:ok, {_a3, auth3}} = WebAuthnAuthenticator.sign_challenge(auth2, options)

      assert auth1.sign_count == 1
      assert auth2.sign_count == 2
      assert auth3.sign_count == 3
    end

    test "signature verifies against the authenticator's public key", %{
      auth: auth,
      assertion: assertion
    } do
      client_data_json_bytes =
        assertion["response"]["clientDataJSON"]
        |> Base.url_decode64!(padding: false)

      auth_data_bytes =
        assertion["response"]["authenticatorData"]
        |> Base.url_decode64!(padding: false)

      signature =
        assertion["response"]["signature"]
        |> Base.url_decode64!(padding: false)

      client_data_hash = :crypto.hash(:sha256, client_data_json_bytes)
      verification_data = auth_data_bytes <> client_data_hash

      assert :crypto.verify(:ecdsa, :sha256, verification_data, signature, [
               auth.public_key_raw,
               :prime256v1
             ])
    end
  end
end
