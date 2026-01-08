defmodule Authify.MFATest do
  @moduledoc """
  Tests for MFA (Multi-Factor Authentication) module.
  """
  use Authify.DataCase

  alias Authify.Accounts.User
  alias Authify.MFA

  import Authify.AccountsFixtures

  describe "setup_totp/1" do
    test "generates a TOTP secret for user without TOTP" do
      user = user_fixture()

      assert {:ok, secret} = MFA.setup_totp(user)
      assert is_binary(secret)
      # NimbleTOTP secrets are 20 bytes (160 bits)
      assert byte_size(secret) == 20
    end

    test "returns error if TOTP already enabled" do
      user = user_fixture()
      {:ok, secret} = MFA.setup_totp(user)

      # Enable TOTP
      valid_code = NimbleTOTP.verification_code(secret)
      {:ok, user_with_totp, _codes} = MFA.complete_totp_setup(user, valid_code, secret)

      # Try to setup again
      assert {:error, :totp_already_enabled} = MFA.setup_totp(user_with_totp)
    end
  end

  describe "complete_totp_setup/3" do
    test "enables TOTP with valid verification code" do
      user = user_fixture()
      {:ok, secret} = MFA.setup_totp(user)

      # Generate a valid TOTP code
      code = NimbleTOTP.verification_code(secret)

      assert {:ok, updated_user, backup_codes} = MFA.complete_totp_setup(user, code, secret)
      assert updated_user.totp_enabled_at != nil
      assert updated_user.totp_secret != nil
      assert updated_user.totp_backup_codes != nil
      assert is_list(backup_codes)
      assert length(backup_codes) == 10

      # Verify all backup codes are formatted correctly (XXXX-XXXX)
      Enum.each(backup_codes, fn code ->
        assert code =~ ~r/^[A-Z0-9]{4}-[A-Z0-9]{4}$/
      end)
    end

    test "rejects invalid verification code" do
      user = user_fixture()
      {:ok, secret} = MFA.setup_totp(user)

      assert {:error, :invalid_verification_code} =
               MFA.complete_totp_setup(user, "000000", secret)
    end
  end

  describe "verify_totp/2" do
    setup do
      user = user_fixture()
      {:ok, secret} = MFA.setup_totp(user)
      code = NimbleTOTP.verification_code(secret)
      {:ok, user_with_totp, _codes} = MFA.complete_totp_setup(user, code, secret)

      # Store the secret for generating codes in tests
      %{user: user_with_totp, secret: secret}
    end

    test "accepts valid TOTP code", %{user: user, secret: secret} do
      code = NimbleTOTP.verification_code(secret)
      assert {:ok, ^user} = MFA.verify_totp(user, code)
    end

    test "rejects invalid TOTP code", %{user: user} do
      assert {:error, :invalid_code} = MFA.verify_totp(user, "000000")
    end

    test "returns error for user without TOTP enabled" do
      user = user_fixture()
      assert {:error, :totp_not_enabled} = MFA.verify_totp(user, "123456")
    end
  end

  describe "disable_totp/1" do
    setup do
      user = user_fixture()
      {:ok, secret} = MFA.setup_totp(user)
      code = NimbleTOTP.verification_code(secret)
      {:ok, user_with_totp, _codes} = MFA.complete_totp_setup(user, code, secret)

      %{user: user_with_totp}
    end

    test "clears TOTP data", %{user: user} do
      assert {:ok, updated_user} = MFA.disable_totp(user)
      assert updated_user.totp_secret == nil
      assert updated_user.totp_enabled_at == nil
      assert updated_user.totp_backup_codes == nil
      assert updated_user.totp_backup_codes_generated_at == nil
    end
  end

  describe "backup codes" do
    setup do
      user = user_fixture()
      {:ok, secret} = MFA.setup_totp(user)
      code = NimbleTOTP.verification_code(secret)
      {:ok, user_with_totp, backup_codes} = MFA.complete_totp_setup(user, code, secret)

      %{user: user_with_totp, backup_codes: backup_codes}
    end

    test "verify_backup_code/2 accepts valid backup code", %{user: user, backup_codes: codes} do
      code = List.first(codes)
      assert {:ok, updated_user} = MFA.verify_backup_code(user, code)

      # Code should be consumed (count reduced by 1)
      assert MFA.backup_codes_count(updated_user) == 9
    end

    test "verify_backup_code/2 rejects invalid backup code", %{user: user} do
      assert {:error, :invalid_code} = MFA.verify_backup_code(user, "INVALID-CODE")
    end

    test "verify_backup_code/2 rejects already-used backup code", %{
      user: user,
      backup_codes: codes
    } do
      code = List.first(codes)

      # Use the code once
      {:ok, updated_user} = MFA.verify_backup_code(user, code)

      # Try to use it again
      assert {:error, :invalid_code} = MFA.verify_backup_code(updated_user, code)
    end

    test "backup_codes_count/1 returns correct count", %{user: user} do
      assert MFA.backup_codes_count(user) == 10
    end

    test "regenerate_backup_codes/1 generates new codes", %{user: user, backup_codes: old_codes} do
      assert {:ok, updated_user, new_codes} = MFA.regenerate_backup_codes(user)
      assert is_list(new_codes)
      assert length(new_codes) == 10
      assert new_codes != old_codes

      # Old codes should not work
      old_code = List.first(old_codes)
      assert {:error, :invalid_code} = MFA.verify_backup_code(updated_user, old_code)

      # New codes should work
      new_code = List.first(new_codes)
      assert {:ok, _} = MFA.verify_backup_code(updated_user, new_code)
    end
  end

  describe "trusted devices" do
    setup do
      user = user_fixture()
      %{user: user}
    end

    test "create_trusted_device/2 creates a new trusted device", %{user: user} do
      device_info = %{
        device_name: "Test Device",
        ip_address: "192.168.1.1",
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/91.0"
      }

      assert {:ok, device, token} = MFA.create_trusted_device(user, device_info)
      assert device.user_id == user.id
      assert device.device_name == "Test Device"
      assert device.ip_address == "192.168.1.1"
      assert device.expires_at != nil
      assert String.starts_with?(token, "authify_device_")
    end

    test "create_trusted_device/2 extracts device name from user agent", %{user: user} do
      device_info = %{
        user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)"
      }

      assert {:ok, device, _token} = MFA.create_trusted_device(user, device_info)
      assert device.device_name == "iPhone"
    end

    test "verify_trusted_device/2 verifies valid device token", %{user: user} do
      device_info = %{device_name: "Test Device"}
      {:ok, _device, token} = MFA.create_trusted_device(user, device_info)

      assert {:ok, verified_device} = MFA.verify_trusted_device(user, token)
      assert verified_device.user_id == user.id
    end

    test "verify_trusted_device/2 rejects invalid token", %{user: user} do
      assert {:error, :device_not_found_or_expired} =
               MFA.verify_trusted_device(user, "authify_device_invalid")
    end

    test "verify_trusted_device/2 rejects expired device", %{user: user} do
      device_info = %{device_name: "Test Device"}
      {:ok, device, token} = MFA.create_trusted_device(user, device_info)

      # Manually expire the device
      expired_at = DateTime.utc_now() |> DateTime.add(-1, :day) |> DateTime.truncate(:second)

      device
      |> Ecto.Changeset.change(%{expires_at: expired_at})
      |> Repo.update!()

      assert {:error, :device_not_found_or_expired} = MFA.verify_trusted_device(user, token)
    end

    test "list_trusted_devices/1 returns user's devices", %{user: user} do
      {:ok, _device1, _token1} = MFA.create_trusted_device(user, %{device_name: "Device 1"})
      {:ok, _device2, _token2} = MFA.create_trusted_device(user, %{device_name: "Device 2"})

      devices = MFA.list_trusted_devices(user)
      assert length(devices) == 2
    end

    test "revoke_trusted_device/1 deletes a device", %{user: user} do
      {:ok, device, _token} = MFA.create_trusted_device(user, %{device_name: "Test Device"})

      assert {:ok, _} = MFA.revoke_trusted_device(device.id)
      assert MFA.list_trusted_devices(user) == []
    end

    test "revoke_all_trusted_devices/1 deletes all user devices", %{user: user} do
      {:ok, _device1, _token1} = MFA.create_trusted_device(user, %{device_name: "Device 1"})
      {:ok, _device2, _token2} = MFA.create_trusted_device(user, %{device_name: "Device 2"})

      assert {:ok, 2} = MFA.revoke_all_trusted_devices(user)
      assert MFA.list_trusted_devices(user) == []
    end
  end

  describe "lockout management" do
    setup do
      user = user_fixture()
      %{user: user}
    end

    test "check_lockout/1 returns no lockout for unlocked user", %{user: user} do
      assert {:ok, :no_lockout} = MFA.check_lockout(user)
    end

    test "unlock_user/2 unlocks a locked user", %{user: user} do
      admin = user_fixture()

      # Create a lockout
      locked_until = DateTime.utc_now() |> DateTime.add(5, :minute)

      %Authify.MFA.TotpLockout{}
      |> Authify.MFA.TotpLockout.changeset(%{
        user_id: user.id,
        locked_at: DateTime.utc_now(),
        locked_until: locked_until,
        failed_attempts: 5
      })
      |> Repo.insert!()

      # Verify user is locked
      assert {:error, {:locked, _}} = MFA.check_lockout(user)

      # Unlock
      assert {:ok, _} = MFA.unlock_user(user, admin)

      # Verify user is unlocked
      assert {:ok, :no_lockout} = MFA.check_lockout(user)
    end
  end

  describe "User helper functions" do
    test "totp_enabled?/1 returns false for user without TOTP" do
      user = user_fixture()
      refute User.totp_enabled?(user)
    end

    test "totp_enabled?/1 returns true for user with TOTP" do
      user = user_fixture()
      {:ok, secret} = MFA.setup_totp(user)
      code = NimbleTOTP.verification_code(secret)
      {:ok, user_with_totp, _codes} = MFA.complete_totp_setup(user, code, secret)

      assert User.totp_enabled?(user_with_totp)
    end
  end
end
