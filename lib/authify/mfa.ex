defmodule Authify.MFA do
  @moduledoc """
  Multi-Factor Authentication context.

  Handles TOTP enrollment, verification, backup codes, trusted devices,
  and lockout management.
  """

  import Ecto.Query
  alias Authify.Accounts.User
  alias Authify.Encryption
  alias Authify.MFA.{TotpLockout, TrustedDevice}
  alias Authify.Repo

  # TOTP Functions

  @doc """
  Initializes TOTP setup by generating a secret.
  Returns a tuple with the plaintext secret (for QR code) and user with virtual field set.
  """
  def setup_totp(%User{totp_enabled_at: nil}) do
    # Generate a new TOTP secret (Base32-encoded, 160 bits = 32 characters)
    secret = NimbleTOTP.secret()

    {:ok, secret}
  end

  def setup_totp(%User{}), do: {:error, :totp_already_enabled}

  @doc """
  Completes TOTP setup by verifying the code and enabling TOTP.
  """
  def complete_totp_setup(%User{} = user, verification_code, plaintext_secret)
      when is_binary(verification_code) and is_binary(plaintext_secret) do
    # Verify the code against the secret
    if NimbleTOTP.valid?(plaintext_secret, verification_code) do
      # Encrypt the secret for storage
      encrypted_secret = Encryption.encrypt(plaintext_secret)

      # Generate backup codes
      {plaintext_codes, hashed_codes} = generate_backup_codes()

      # Update user with encrypted secret and backup codes
      user
      |> Ecto.Changeset.change(%{
        totp_secret: encrypted_secret,
        totp_enabled_at: DateTime.utc_now() |> DateTime.truncate(:second),
        totp_backup_codes: Jason.encode!(hashed_codes),
        totp_backup_codes_generated_at: DateTime.utc_now() |> DateTime.truncate(:second)
      })
      |> Repo.update()
      |> case do
        {:ok, updated_user} -> {:ok, updated_user, plaintext_codes}
        {:error, changeset} -> {:error, changeset}
      end
    else
      {:error, :invalid_verification_code}
    end
  end

  @doc """
  Verifies a TOTP code for a user.
  """
  def verify_totp(%User{totp_secret: encrypted_secret} = user, code)
      when is_binary(encrypted_secret) and is_binary(code) do
    # Decrypt the secret
    case Encryption.decrypt(encrypted_secret) do
      {:ok, plaintext_secret} ->
        # Verify the code
        if NimbleTOTP.valid?(plaintext_secret, code) do
          {:ok, user}
        else
          {:error, :invalid_code}
        end

      {:error, _reason} ->
        {:error, :decryption_failed}
    end
  end

  def verify_totp(%User{totp_secret: nil}, _code), do: {:error, :totp_not_enabled}

  @doc """
  Disables TOTP for a user by clearing TOTP data and revoking all trusted devices.
  """
  def disable_totp(%User{} = user) do
    Repo.transaction(fn ->
      # Clear TOTP data
      updated_user =
        user
        |> Ecto.Changeset.change(%{
          totp_secret: nil,
          totp_enabled_at: nil,
          totp_backup_codes: nil,
          totp_backup_codes_generated_at: nil
        })
        |> Repo.update!()

      # Revoke all trusted devices
      revoke_all_trusted_devices(user)

      updated_user
    end)
  end

  # Backup Code Functions

  @doc """
  Generates 10 backup codes.
  Returns {plaintext_codes, hashed_codes}.
  """
  def generate_backup_codes(count \\ 10) do
    codes =
      1..count
      |> Enum.map(fn _ ->
        # Generate 8 random alphanumeric characters
        code =
          :crypto.strong_rand_bytes(6)
          |> Base.encode32(padding: false)
          |> binary_part(0, 8)

        # Format as XXXX-XXXX for readability
        formatted = String.slice(code, 0..3) <> "-" <> String.slice(code, 4..7)

        # Return {plaintext, bcrypt_hash}
        {formatted, Bcrypt.hash_pwd_salt(formatted)}
      end)
      |> Enum.unzip()

    codes
  end

  @doc """
  Verifies a backup code and consumes it (removes from list).
  """
  def verify_backup_code(%User{totp_backup_codes: codes_json} = user, submitted_code)
      when is_binary(codes_json) and is_binary(submitted_code) do
    # Parse stored hashes
    case Jason.decode(codes_json) do
      {:ok, hashed_codes} when is_list(hashed_codes) ->
        # Check if any hash matches
        case Enum.find_index(hashed_codes, &Bcrypt.verify_pass(submitted_code, &1)) do
          nil ->
            {:error, :invalid_code}

          index ->
            # Remove used code from list
            remaining_codes = List.delete_at(hashed_codes, index)

            # Update user with remaining codes
            user
            |> Ecto.Changeset.change(%{
              totp_backup_codes: Jason.encode!(remaining_codes)
            })
            |> Repo.update()
            |> case do
              {:ok, updated_user} -> {:ok, updated_user}
              {:error, changeset} -> {:error, changeset}
            end
        end

      _ ->
        {:error, :no_codes}
    end
  end

  def verify_backup_code(%User{}, _code), do: {:error, :no_codes}

  @doc """
  Regenerates backup codes for a user.
  """
  def regenerate_backup_codes(%User{} = user) do
    {plaintext_codes, hashed_codes} = generate_backup_codes()

    user
    |> Ecto.Changeset.change(%{
      totp_backup_codes: Jason.encode!(hashed_codes),
      totp_backup_codes_generated_at: DateTime.utc_now() |> DateTime.truncate(:second)
    })
    |> Repo.update()
    |> case do
      {:ok, updated_user} -> {:ok, updated_user, plaintext_codes}
      {:error, changeset} -> {:error, changeset}
    end
  end

  @doc """
  Gets the count of remaining backup codes.
  """
  def backup_codes_count(%User{totp_backup_codes: codes_json}) when is_binary(codes_json) do
    case Jason.decode(codes_json) do
      {:ok, codes} when is_list(codes) -> length(codes)
      _ -> 0
    end
  end

  def backup_codes_count(%User{}), do: 0

  # Trusted Device Functions

  @doc """
  Creates a trusted device for a user.
  Returns {:ok, device, plaintext_token} or {:error, changeset}.
  """
  def create_trusted_device(%User{} = user, device_info) do
    # Generate random token
    plaintext_token =
      :crypto.strong_rand_bytes(32)
      |> Base.url_encode64(padding: false)

    # Prefix for identification
    prefixed_token = "authify_device_" <> plaintext_token

    # Hash token for storage (SHA-256)
    token_hash =
      :crypto.hash(:sha256, prefixed_token)
      |> Base.encode64()

    # Set expiry to 30 days from now
    expires_at =
      DateTime.utc_now()
      |> DateTime.add(30, :day)
      |> DateTime.truncate(:second)

    # Extract device info
    device_name = device_info[:device_name] || extract_device_name(device_info[:user_agent])
    ip_address = device_info[:ip_address]
    user_agent = device_info[:user_agent]

    %TrustedDevice{}
    |> TrustedDevice.changeset(%{
      user_id: user.id,
      device_token: token_hash,
      device_name: device_name,
      ip_address: ip_address,
      user_agent: user_agent,
      last_used_at: DateTime.utc_now() |> DateTime.truncate(:second),
      expires_at: expires_at
    })
    |> Repo.insert()
    |> case do
      {:ok, device} -> {:ok, device, prefixed_token}
      {:error, changeset} -> {:error, changeset}
    end
  end

  @doc """
  Verifies a trusted device token.
  Returns {:ok, device} if valid and not expired, {:error, reason} otherwise.
  """
  def verify_trusted_device(%User{} = user, plaintext_token) when is_binary(plaintext_token) do
    # Hash the token
    token_hash =
      :crypto.hash(:sha256, plaintext_token)
      |> Base.encode64()

    # Find the device
    query =
      from d in TrustedDevice,
        where:
          d.user_id == ^user.id and
            d.device_token == ^token_hash and
            d.expires_at > ^DateTime.utc_now(),
        limit: 1

    case Repo.one(query) do
      nil ->
        {:error, :device_not_found_or_expired}

      device ->
        # Update last used timestamp
        device
        |> Ecto.Changeset.change(%{
          last_used_at: DateTime.utc_now() |> DateTime.truncate(:second)
        })
        |> Repo.update()

        {:ok, device}
    end
  end

  def verify_trusted_device(_, _), do: {:error, :invalid_token}

  @doc """
  Lists all trusted devices for a user.
  """
  def list_trusted_devices(%User{} = user) do
    query =
      from d in TrustedDevice,
        where: d.user_id == ^user.id and d.expires_at > ^DateTime.utc_now(),
        order_by: [desc: d.last_used_at]

    Repo.all(query)
  end

  @doc """
  Revokes a specific trusted device.
  """
  def revoke_trusted_device(device_id) when is_integer(device_id) do
    case Repo.get(TrustedDevice, device_id) do
      nil -> {:error, :not_found}
      device -> Repo.delete(device)
    end
  end

  @doc """
  Revokes all trusted devices for a user.
  """
  def revoke_all_trusted_devices(%User{} = user) do
    query = from d in TrustedDevice, where: d.user_id == ^user.id

    {count, _} = Repo.delete_all(query)
    {:ok, count}
  end

  # Lockout Functions

  @doc """
  Checks if a user is currently locked out.
  Returns {:ok, :no_lockout} or {:error, {:locked, locked_until}}.
  """
  def check_lockout(%User{} = user) do
    query =
      from l in TotpLockout,
        where:
          l.user_id == ^user.id and
            is_nil(l.unlocked_at) and
            l.locked_until > ^DateTime.utc_now(),
        order_by: [desc: l.locked_at],
        limit: 1

    case Repo.one(query) do
      nil -> {:ok, :no_lockout}
      lockout -> {:error, {:locked, lockout.locked_until}}
    end
  end

  @doc """
  Unlocks a user by marking all active lockouts as unlocked.
  """
  def unlock_user(%User{} = user, admin_user) do
    query =
      from l in TotpLockout,
        where: l.user_id == ^user.id and is_nil(l.unlocked_at)

    Repo.update_all(query,
      set: [
        unlocked_at: DateTime.utc_now() |> DateTime.truncate(:second),
        unlocked_by_admin_id: admin_user.id
      ]
    )

    # Also clear any rate limit buckets (TODO: implement when RateLimit module is ready)
    # Authify.RateLimit.delete_buckets("mfa:totp:#{user.id}")

    {:ok, user}
  end

  # Admin Functions

  @doc """
  Admin reset of TOTP - clears all TOTP data and trusted devices.
  """
  def admin_reset_totp(%User{} = user, _admin_user) do
    Repo.transaction(fn ->
      # Use disable_totp to clear data
      {:ok, updated_user} = disable_totp(user)

      # Log the admin action (this will be handled by controller)
      updated_user
    end)
  end

  # Helper Functions

  defp extract_device_name(nil), do: "Unknown Device"

  defp extract_device_name(user_agent) when is_binary(user_agent) do
    cond do
      String.contains?(user_agent, "Chrome") ->
        "Chrome Browser"

      String.contains?(user_agent, "Firefox") ->
        "Firefox Browser"

      String.contains?(user_agent, "Safari") && !String.contains?(user_agent, "Chrome") ->
        "Safari Browser"

      String.contains?(user_agent, "Edge") ->
        "Edge Browser"

      String.contains?(user_agent, "iPhone") ->
        "iPhone"

      String.contains?(user_agent, "Android") ->
        "Android Device"

      String.contains?(user_agent, "iPad") ->
        "iPad"

      true ->
        "Unknown Device"
    end
  end

  @doc """
  Helper to check if TOTP is enabled for a user.
  Delegates to User module.
  """
  defdelegate totp_enabled?(user), to: User
end
