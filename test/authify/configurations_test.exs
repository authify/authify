defmodule Authify.ConfigurationsTest do
  use Authify.DataCase

  alias Authify.Configurations
  alias Authify.Configurations.Schemas.Global
  import Authify.AccountsFixtures

  describe "global configuration" do
    test "get_global_configuration/0 returns or creates global configuration" do
      config = Configurations.get_global_configuration()
      assert config
      assert config.schema_name == "global"
      assert config.configurable_type == "Organization"
    end

    test "get_global_setting/1 returns default value when not set" do
      # allow_organization_registration should default to false
      assert Configurations.get_global_setting(:allow_organization_registration) == false
    end

    test "set_global_setting/2 sets and persists global setting" do
      {:ok, _} = Configurations.set_global_setting(:allow_organization_registration, true)
      assert Configurations.get_global_setting(:allow_organization_registration) == true

      # Verify it persists
      assert Configurations.get_global_setting(:allow_organization_registration) == true
    end

    test "set_global_setting/2 validates boolean values" do
      # String "true" should be cast to boolean
      {:ok, _} = Configurations.set_global_setting(:allow_organization_registration, "true")
      assert Configurations.get_global_setting(:allow_organization_registration) == true

      {:ok, _} = Configurations.set_global_setting(:allow_organization_registration, "false")
      assert Configurations.get_global_setting(:allow_organization_registration) == false
    end

    test "set_global_setting/2 validates email format for support_email" do
      {:ok, _} = Configurations.set_global_setting(:support_email, "support@example.com")
      assert Configurations.get_global_setting(:support_email) == "support@example.com"

      {:error, _} = Configurations.set_global_setting(:support_email, "invalid-email")
    end

    test "get_all_settings/2 returns map of all settings" do
      Configurations.set_global_setting(:site_name, "My Authify Instance")
      Configurations.set_global_setting(:allow_organization_registration, true)

      global_org = Authify.Accounts.get_global_organization()
      settings = Configurations.get_all_settings("Organization", global_org.id)

      assert is_map(settings)
      assert settings[:allow_organization_registration] == true
      assert settings[:site_name] == "My Authify Instance"
      # Default values should be included
    end
  end

  describe "configuration schemas" do
    test "Global schema has expected settings" do
      settings = Global.settings()

      assert is_list(settings)
      assert Enum.any?(settings, &(&1.name == :allow_organization_registration))
      assert Enum.any?(settings, &(&1.name == :site_name))
      assert Enum.any?(settings, &(&1.name == :support_email))
    end

    test "Global schema validates boolean correctly" do
      assert {:ok, true} = Global.validate_value(:allow_organization_registration, true)
      assert {:ok, false} = Global.validate_value(:allow_organization_registration, false)
      assert {:ok, true} = Global.validate_value(:allow_organization_registration, "true")
      assert {:ok, false} = Global.validate_value(:allow_organization_registration, "false")
    end

    test "Global schema validates email correctly" do
      assert {:ok, "test@example.com"} = Global.validate_value(:support_email, "test@example.com")
      assert {:error, _} = Global.validate_value(:support_email, "invalid")
    end
  end

  describe "organization configuration" do
    test "organization can have its own configuration" do
      org = organization_fixture()

      config =
        Configurations.get_or_create_configuration("Organization", org.id, "organization")

      assert config
      assert config.schema_name == "organization"
      assert config.configurable_id == org.id
    end

    test "get_setting/3 returns default when not set" do
      org = organization_fixture()
      Configurations.get_or_create_configuration("Organization", org.id, "organization")

      # Should return default value (true for allow_invitations)
      value = Configurations.get_setting("Organization", org.id, :allow_invitations)
      assert value == true
    end

    test "set_setting/4 and get_setting/3 work for organization config" do
      org = organization_fixture()
      Configurations.get_or_create_configuration("Organization", org.id, "organization")

      {:ok, _} = Configurations.set_setting("Organization", org.id, :allow_invitations, false)

      value = Configurations.get_setting("Organization", org.id, :allow_invitations)
      assert value == false
    end

    test "organizations have isolated configurations" do
      org1 = organization_fixture()
      org2 = organization_fixture()

      Configurations.get_or_create_configuration("Organization", org1.id, "organization")
      Configurations.get_or_create_configuration("Organization", org2.id, "organization")

      {:ok, _} = Configurations.set_setting("Organization", org1.id, :allow_saml, false)
      {:ok, _} = Configurations.set_setting("Organization", org2.id, :allow_saml, true)

      assert Configurations.get_setting("Organization", org1.id, :allow_saml) == false
      assert Configurations.get_setting("Organization", org2.id, :allow_saml) == true
    end
  end

  describe "configuration value casting" do
    test "casts boolean strings correctly" do
      assert {:ok, true} = Configurations.Schema.cast_value(:boolean, "true")
      assert {:ok, false} = Configurations.Schema.cast_value(:boolean, "false")
      assert {:ok, true} = Configurations.Schema.cast_value(:boolean, "1")
      assert {:ok, false} = Configurations.Schema.cast_value(:boolean, "0")
      assert {:error, _} = Configurations.Schema.cast_value(:boolean, "invalid")
    end

    test "casts integer strings correctly" do
      assert {:ok, 42} = Configurations.Schema.cast_value(:integer, "42")
      assert {:ok, 0} = Configurations.Schema.cast_value(:integer, "0")
      assert {:error, _} = Configurations.Schema.cast_value(:integer, "not_a_number")
      assert {:error, _} = Configurations.Schema.cast_value(:integer, "12.5")
    end

    test "casts float strings correctly" do
      assert {:ok, 3.14} = Configurations.Schema.cast_value(:float, "3.14")
      assert {:ok, 42.0} = Configurations.Schema.cast_value(:float, "42")
      assert {:error, _} = Configurations.Schema.cast_value(:float, "not_a_number")
    end

    test "handles nil values" do
      assert {:ok, nil} = Configurations.Schema.cast_value(:string, nil)
      assert {:ok, nil} = Configurations.Schema.cast_value(:boolean, nil)
      assert {:ok, nil} = Configurations.Schema.cast_value(:integer, nil)
    end
  end

  describe "configuration value storage" do
    test "to_string_value converts values correctly" do
      assert Configurations.Schema.to_string_value(true) == "true"
      assert Configurations.Schema.to_string_value(false) == "false"
      assert Configurations.Schema.to_string_value(42) == "42"
      assert Configurations.Schema.to_string_value(3.14) == "3.14"
      assert Configurations.Schema.to_string_value("text") == "text"
      assert Configurations.Schema.to_string_value(nil) == nil
    end

    test "setting values are stored and retrieved correctly" do
      org = organization_fixture()
      Configurations.get_or_create_configuration("Organization", org.id, "organization")

      # Set various types
      {:ok, _} = Configurations.set_setting("Organization", org.id, :allow_invitations, true)
      {:ok, _} = Configurations.set_setting("Organization", org.id, :allow_saml, false)

      # Retrieve and verify types
      assert Configurations.get_setting("Organization", org.id, :allow_invitations) === true
      assert Configurations.get_setting("Organization", org.id, :allow_saml) === false
    end
  end
end
