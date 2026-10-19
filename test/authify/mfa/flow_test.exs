defmodule Authify.MFA.FlowTest do
  @moduledoc """
  Unit tests for the conn-agnostic MFA flow orchestration module.
  """
  use Authify.DataCase, async: true

  alias Authify.MFA
  alias Authify.MFA.Flow
  alias Authify.MFA.WebAuthnCredential
  alias Authify.Repo

  import Authify.AccountsFixtures

  @png_magic <<0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A>>

  @webauthn_errors %{
    invalid_challenge: "Invalid or expired challenge",
    challenge_already_used: "Challenge has already been used",
    challenge_expired: "Challenge has expired",
    challenge_mismatch: "Challenge verification failed",
    invalid_sign_count: "Security key may be cloned (invalid sign count)",
    credential_not_found: "Security key not recognized",
    credential_not_owned: "Security key not owned by this user",
    decryption_failed: "Failed to decrypt credential data"
  }

  describe "prepare_totp_setup/3" do
    test "returns the URI, QR code, and manual entry key" do
      organization = organization_fixture(%{name: "Acme Corp"})
      user = user_fixture(organization: organization, email: "alice@example.com")
      secret = :crypto.strong_rand_bytes(20)

      setup = Flow.prepare_totp_setup(user, secret, organization)

      assert %{totp_uri: uri, qr_code_data_uri: qr, manual_entry_key: manual} = setup
      assert uri == Flow.build_totp_uri(user, secret, organization)
      assert manual == Flow.format_secret_for_manual_entry(secret)

      assert {:ok, png} = Base.decode64(qr)
      assert String.starts_with?(png, @png_magic)
    end
  end

  describe "build_totp_uri/3" do
    test "builds a well-formed otpauth URI with label, secret, and issuer" do
      organization = organization_fixture(%{name: "Acme Corp"})
      user = user_fixture(organization: organization, email: "alice@example.com")
      secret = :crypto.strong_rand_bytes(20)

      uri = Flow.build_totp_uri(user, secret, organization)
      parsed = URI.parse(uri)

      assert parsed.scheme == "otpauth"
      assert parsed.host == "totp"
      assert URI.decode(parsed.path) == "/Acme Corp:alice@example.com"

      query = URI.decode_query(parsed.query)
      assert query["secret"] == Base.encode32(secret, padding: false)
      assert query["issuer"] == "Acme Corp"
      refute query["secret"] =~ "="
    end

    test "handles an empty secret" do
      organization = organization_fixture(%{name: "Acme Corp"})
      user = user_fixture(organization: organization, email: "alice@example.com")

      uri = Flow.build_totp_uri(user, "", organization)
      query = uri |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

      assert String.starts_with?(uri, "otpauth://totp/")
      assert query["secret"] == ""
    end
  end

  describe "generate_qr_code/1" do
    test "returns a base64-encoded PNG for a valid payload" do
      qr = Flow.generate_qr_code("otpauth://totp/Acme:alice@example.com?secret=ABC&issuer=Acme")

      assert is_binary(qr)
      assert {:ok, png} = Base.decode64(qr)
      assert String.starts_with?(png, @png_magic)
    end

    test "handles an empty payload" do
      qr = Flow.generate_qr_code("")

      assert {:ok, png} = Base.decode64(qr)
      assert String.starts_with?(png, @png_magic)
    end

    test "returns nil for a non-binary payload" do
      assert Flow.generate_qr_code(nil) == nil
    end
  end

  describe "format_secret_for_manual_entry/1" do
    test "base32-encodes the secret in groups of four without padding" do
      secret = :crypto.strong_rand_bytes(20)
      formatted = Flow.format_secret_for_manual_entry(secret)

      groups = String.split(formatted, " ")
      encoded = Base.encode32(secret, padding: false)

      assert Enum.join(groups) == encoded
      assert Enum.all?(groups, &(String.length(&1) <= 4))
      refute formatted =~ "="
    end

    test "returns an empty string for an empty secret" do
      assert Flow.format_secret_for_manual_entry("") == ""
    end
  end

  describe "detect_available_methods/1" do
    test "reports both methods disabled and defaults to TOTP" do
      user = user_fixture()

      assert Flow.detect_available_methods(user) == %{
               default_method: :totp,
               has_totp: false,
               has_webauthn: false
             }
    end

    test "detects TOTP" do
      user = user_fixture() |> enable_totp()

      methods = Flow.detect_available_methods(user)
      assert methods.has_totp
      refute methods.has_webauthn
      assert methods.default_method == :totp
    end

    test "detects WebAuthn and prefers it" do
      user = user_fixture()
      create_credential(user)

      methods = Flow.detect_available_methods(user)
      refute methods.has_totp
      assert methods.has_webauthn
      assert methods.default_method == :webauthn
    end

    test "prefers WebAuthn when both methods are enabled" do
      user = user_fixture() |> enable_totp()
      create_credential(user)

      methods = Flow.detect_available_methods(user)
      assert methods.has_totp
      assert methods.has_webauthn
      assert methods.default_method == :webauthn
    end
  end

  describe "format_webauthn_error/1" do
    test "maps every known error atom to a human-readable message" do
      for {error, message} <- @webauthn_errors do
        assert Flow.format_webauthn_error(error) == message
      end
    end

    test "falls back for unknown atoms and non-atom values" do
      assert Flow.format_webauthn_error(:not_a_known_error) == "Authentication failed"
      assert Flow.format_webauthn_error(nil) == "Authentication failed"
      assert Flow.format_webauthn_error("boom") == "Authentication failed"
    end
  end

  describe "create_trusted_device/3" do
    test "creates a trusted device and returns its token" do
      user = user_fixture()

      token =
        Flow.create_trusted_device(
          user,
          "203.0.113.10",
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0"
        )

      assert is_binary(token)
      assert String.starts_with?(token, "authify_device_")

      assert {:ok, device} = MFA.verify_trusted_device(user, token)
      assert device.user_id == user.id
      assert device.ip_address == "203.0.113.10"
      assert device.device_name == "Chrome Browser"
      assert device.user_agent =~ "Chrome"
    end

    test "uses an unknown device name when the user agent is nil" do
      user = user_fixture()

      token = Flow.create_trusted_device(user, "127.0.0.1", nil)

      assert {:ok, device} = MFA.verify_trusted_device(user, token)
      assert device.device_name == "Unknown Device"
      assert device.user_agent == nil
    end
  end

  defp enable_totp(user) do
    {:ok, secret} = MFA.setup_totp(user)
    code = NimbleTOTP.verification_code(secret)
    {:ok, user, _backup_codes} = MFA.complete_totp_setup(user, code, secret)
    user
  end

  defp create_credential(user) do
    %WebAuthnCredential{}
    |> WebAuthnCredential.changeset(%{
      user_id: user.id,
      organization_id: user.organization_id,
      credential_id: "flow_test_#{System.unique_integer([:positive])}",
      public_key: :crypto.strong_rand_bytes(32),
      sign_count: 0,
      name: "Flow Test Key",
      credential_type: "platform"
    })
    |> Repo.insert!()
  end
end
