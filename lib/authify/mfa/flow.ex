defmodule Authify.MFA.Flow do
  @moduledoc """
  Orchestration logic for MFA flows, extracted from MfaController.
  This module is conn-agnostic and focuses on data preparation and formatting.
  """

  alias Authify.Accounts.User
  alias Authify.MFA

  @doc """
  Prepares all data needed for the TOTP setup view.
  """
  def prepare_totp_setup(user, secret, organization) do
    totp_uri = build_totp_uri(user, secret, organization)

    %{
      totp_uri: totp_uri,
      qr_code_data_uri: generate_qr_code(totp_uri),
      manual_entry_key: format_secret_for_manual_entry(secret)
    }
  end

  @doc """
  Builds the otpauth:// URI for TOTP enrollment.
  """
  def build_totp_uri(user, secret, organization) do
    # Format: otpauth://totp/Authify:user@example.com?secret=BASE32&issuer=OrgName
    label = "#{organization.name}:#{User.get_primary_email_value(user)}"
    issuer = organization.name
    # Base32-encode the binary secret for the URI (without padding per TOTP spec)
    base32_secret = Base.encode32(secret, padding: false)

    "otpauth://totp/#{URI.encode(label)}?secret=#{base32_secret}&issuer=#{URI.encode(issuer)}"
  end

  @doc """
  Generates a QR code as PNG data URI from the otpauth:// URI.
  """
  def generate_qr_code(uri) do
    uri
    |> EQRCode.encode()
    |> EQRCode.png()
    |> Base.encode64()
  end

  @doc """
  Formats binary secret as base32 groups of 4 for manual entry.
  """
  def format_secret_for_manual_entry(secret) do
    # Base32-encode the binary secret first, then format as groups of 4 for readability
    secret
    |> Base.encode32(padding: false)
    |> String.graphemes()
    |> Enum.chunk_every(4)
    |> Enum.map_join(" ", &Enum.join/1)
  end

  @doc """
  Detects available MFA methods for a user and determines the default method.
  """
  def detect_available_methods(user) do
    # Determine which MFA methods are available
    has_totp = User.totp_enabled?(user)
    has_webauthn = not Enum.empty?(MFA.WebAuthn.list_credentials(user))

    # Prefer WebAuthn if available (more secure - phishing-resistant)
    default_method =
      cond do
        has_webauthn -> :webauthn
        has_totp -> :totp
        true -> :totp
      end

    %{
      default_method: default_method,
      has_totp: has_totp,
      has_webauthn: has_webauthn
    }
  end

  @doc """
  Formats WebAuthn error atoms into human-readable strings.
  """
  def format_webauthn_error(:invalid_challenge), do: "Invalid or expired challenge"
  def format_webauthn_error(:challenge_already_used), do: "Challenge has already been used"
  def format_webauthn_error(:challenge_expired), do: "Challenge has expired"
  def format_webauthn_error(:challenge_mismatch), do: "Challenge verification failed"

  def format_webauthn_error(:invalid_sign_count),
    do: "Security key may be cloned (invalid sign count)"

  def format_webauthn_error(:credential_not_found), do: "Security key not recognized"
  def format_webauthn_error(:credential_not_owned), do: "Security key not owned by this user"
  def format_webauthn_error(:decryption_failed), do: "Failed to decrypt credential data"
  def format_webauthn_error(_), do: "Authentication failed"

  @doc """
  Creates a trusted device for the user.
  """
  def create_trusted_device(user, ip, user_agent) do
    device_info = %{
      ip_address: ip,
      user_agent: user_agent
    }

    case MFA.create_trusted_device(user, device_info) do
      {:ok, _device, token} -> token
      {:error, _} -> nil
    end
  end
end
