defmodule Authify.Configurations.EncryptedSettingsTest do
  use Authify.DataCase

  alias Authify.Configurations

  import Authify.AccountsFixtures

  describe "encrypted configuration values" do
    setup do
      organization = organization_fixture()
      %{organization: organization}
    end

    test "smtp_password is encrypted in database but decrypted when retrieved", %{
      organization: organization
    } do
      # Set the SMTP password
      password = "super_secret_password_123"

      {:ok, _} = Configurations.set_organization_setting(organization, :smtp_password, password)

      # Check that it's encrypted in the database
      config = Configurations.get_configuration("Organization", organization.id)

      stored_value =
        config.configuration_values
        |> Enum.find(&(&1.setting_name == "smtp_password"))
        |> Map.get(:value)

      # Should NOT be the plaintext password
      refute stored_value == password

      # Should be base64 encoded (encrypted format)
      assert String.match?(stored_value, ~r/^[A-Za-z0-9+\/]+=*$/)

      # Retrieve the password - should be decrypted
      retrieved = Configurations.get_organization_setting(organization, :smtp_password)
      assert retrieved == password
    end

    test "non-encrypted settings are stored as plaintext", %{organization: organization} do
      # Set a non-encrypted setting
      {:ok, _} =
        Configurations.set_organization_setting(organization, :smtp_server, "smtp.gmail.com")

      # Check that it's NOT encrypted in the database
      config = Configurations.get_configuration("Organization", organization.id)

      stored_value =
        config.configuration_values
        |> Enum.find(&(&1.setting_name == "smtp_server"))
        |> Map.get(:value)

      # Should be the plaintext value
      assert stored_value == "smtp.gmail.com"

      # Retrieved value should also match
      retrieved = Configurations.get_organization_setting(organization, :smtp_server)
      assert retrieved == "smtp.gmail.com"
    end

    test "updating encrypted password re-encrypts with new value", %{organization: organization} do
      # Set initial password
      {:ok, _} =
        Configurations.set_organization_setting(organization, :smtp_password, "password1")

      config1 = Configurations.get_configuration("Organization", organization.id)

      encrypted1 =
        config1.configuration_values
        |> Enum.find(&(&1.setting_name == "smtp_password"))
        |> Map.get(:value)

      # Update password
      {:ok, _} =
        Configurations.set_organization_setting(organization, :smtp_password, "password2")

      config2 = Configurations.get_configuration("Organization", organization.id)

      encrypted2 =
        config2.configuration_values
        |> Enum.find(&(&1.setting_name == "smtp_password"))
        |> Map.get(:value)

      # Encrypted values should be different (different salt/IV)
      refute encrypted1 == encrypted2

      # But decrypted value should be the new password
      retrieved = Configurations.get_organization_setting(organization, :smtp_password)
      assert retrieved == "password2"
    end

    test "empty password is not encrypted", %{organization: organization} do
      # Set empty password
      {:ok, _} = Configurations.set_organization_setting(organization, :smtp_password, "")

      config = Configurations.get_configuration("Organization", organization.id)

      config_value =
        config.configuration_values
        |> Enum.find(&(&1.setting_name == "smtp_password"))

      # Empty string gets stored as nil or empty
      stored_value = if config_value, do: config_value.value, else: nil
      assert stored_value in [nil, ""]

      # Retrieved value should also be nil/empty
      retrieved = Configurations.get_organization_setting(organization, :smtp_password)
      assert retrieved == nil
    end

    test "nil password is not encrypted", %{organization: organization} do
      # Set nil password
      {:ok, _} = Configurations.set_organization_setting(organization, :smtp_password, nil)

      # Retrieved value should be nil
      retrieved = Configurations.get_organization_setting(organization, :smtp_password)
      assert retrieved == nil
    end

    test "encrypted values work with get_all_settings", %{organization: organization} do
      # Set multiple SMTP settings including encrypted password
      {:ok, _} =
        Configurations.set_organization_setting(organization, :smtp_server, "smtp.example.com")

      {:ok, _} =
        Configurations.set_organization_setting(organization, :smtp_username, "user@example.com")

      {:ok, _} =
        Configurations.set_organization_setting(organization, :smtp_password, "secret_pass")

      # Get all settings
      settings = Configurations.get_all_settings("Organization", organization.id)

      # Password should be decrypted in the returned map
      assert settings[:smtp_password] == "secret_pass"
      assert settings[:smtp_server] == "smtp.example.com"
      assert settings[:smtp_username] == "user@example.com"
    end
  end
end
