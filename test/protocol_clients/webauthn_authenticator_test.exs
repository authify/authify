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
end
