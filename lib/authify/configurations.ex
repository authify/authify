defmodule Authify.Configurations do
  @moduledoc """
  The Configurations context.

  Manages configuration for different entities (organizations, global settings, etc.)
  using a flexible schema-based system.
  """

  import Ecto.Query, warn: false
  alias Authify.Repo

  alias Authify.Configurations.{Configuration, ConfigurationValue, Schema}
  alias Authify.Configurations.Schemas

  @doc """
  Gets or creates a configuration for a given configurable entity.

  ## Examples

      iex> get_or_create_configuration("Organization", 1, "global")
      %Configuration{}

  """
  def get_or_create_configuration(configurable_type, configurable_id, schema_name) do
    case get_configuration(configurable_type, configurable_id) do
      nil ->
        %Configuration{}
        |> Configuration.changeset(%{
          configurable_type: configurable_type,
          configurable_id: configurable_id,
          schema_name: schema_name
        })
        |> Repo.insert!()
        |> Repo.preload(:configuration_values)

      config ->
        Repo.preload(config, :configuration_values)
    end
  end

  @doc """
  Gets a configuration for a given configurable entity.
  """
  def get_configuration(configurable_type, configurable_id) do
    Repo.one(
      from c in Configuration,
        where:
          c.configurable_type == ^configurable_type and c.configurable_id == ^configurable_id,
        preload: :configuration_values
    )
  end

  @doc """
  Gets a setting value for a configurable entity.

  Returns the value if set, otherwise returns the default from the schema.

  Uses an ETS-based cache with 60-second TTL to avoid repeated database queries.

  ## Examples

      iex> get_setting("Organization", 1, :allow_invitations)
      true

  """
  def get_setting(configurable_type, configurable_id, setting_name) do
    # Try cache first
    case Authify.Configurations.Cache.get(configurable_type, configurable_id, setting_name) do
      {:ok, cached_value} ->
        cached_value

      :miss ->
        # Cache miss - fetch from database
        value = fetch_and_cache_setting(configurable_type, configurable_id, setting_name)
        value
    end
  end

  defp fetch_and_cache_setting(configurable_type, configurable_id, setting_name) do
    config = get_configuration(configurable_type, configurable_id)
    schema_module = get_schema_module(config)

    value =
      if config do
        config.configuration_values
        |> Enum.find(&(&1.setting_name == to_string(setting_name)))
        |> case do
          nil -> nil
          config_value -> config_value.value
        end
      end

    # If no value is set, use the default from schema
    result =
      if value do
        setting = Schema.get_setting(schema_module, setting_name)

        # Decrypt if encrypted
        decrypted_value = maybe_decrypt_value(schema_module, setting_name, value)

        case Schema.cast_value(setting.value_type, decrypted_value) do
          {:ok, casted} -> casted
          _ -> Schema.get_default(schema_module, setting_name)
        end
      else
        Schema.get_default(schema_module, setting_name)
      end

    # Cache the result (including defaults)
    Authify.Configurations.Cache.put(configurable_type, configurable_id, setting_name, result)

    result
  end

  @doc """
  Sets a setting value for a configurable entity.

  ## Examples

      iex> set_setting("Organization", 1, :allow_invitations, true)
      {:ok, %ConfigurationValue{}}

  """
  def set_setting(configurable_type, configurable_id, setting_name, value) do
    config = get_configuration(configurable_type, configurable_id)

    unless config do
      raise "Configuration not found. Call get_or_create_configuration first."
    end

    schema_module = get_schema_module(config)

    # Validate the value
    case schema_module.validate_value(setting_name, value) do
      {:ok, validated_value} ->
        string_value = Schema.to_string_value(validated_value)

        # Encrypt if the setting is marked as encrypted
        final_value = maybe_encrypt_value(schema_module, setting_name, string_value)

        upsert_configuration_value(config, setting_name, final_value)

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Gets all settings for a configurable entity as a map.

  Includes both set values and defaults from the schema.
  """
  def get_all_settings(configurable_type, configurable_id) do
    config = get_configuration(configurable_type, configurable_id)
    schema_module = get_schema_module(config)

    # Get all settings from schema
    schema_module.settings()
    |> Enum.map(fn setting ->
      value = get_setting(configurable_type, configurable_id, setting.name)
      {setting.name, value}
    end)
    |> Enum.into(%{})
  end

  @doc """
  Gets the global configuration (for authify-global organization).
  """
  def get_global_configuration do
    # Get the global organization
    global_org = Authify.Accounts.get_global_organization()
    get_or_create_configuration("Organization", global_org.id, "global")
  end

  @doc """
  Gets a global setting value.
  """
  def get_global_setting(setting_name) do
    global_org = Authify.Accounts.get_global_organization()
    get_setting("Organization", global_org.id, setting_name)
  end

  @doc """
  Sets a global setting value.
  """
  def set_global_setting(setting_name, value) do
    global_org = Authify.Accounts.get_global_organization()

    # Ensure configuration exists
    get_or_create_configuration("Organization", global_org.id, "global")

    set_setting("Organization", global_org.id, setting_name, value)
  end

  @doc """
  Gets an organization-specific setting value.
  """
  def get_organization_setting(org, setting_name) do
    # Ensure configuration exists
    get_or_create_configuration("Organization", org.id, "organization")

    get_setting("Organization", org.id, setting_name)
  end

  @doc """
  Sets an organization-specific setting value.

  For rate limit settings, validates against quotas.
  For super_admin_only settings, returns error (use set_organization_setting_as_admin/3).
  """
  def set_organization_setting(org, setting_name, value) do
    set_organization_setting_with_user(org, nil, setting_name, value)
  end

  @doc """
  Sets an organization-specific setting value with user permission checks.

  Checks if the setting is super_admin_only and validates user permissions.
  For rate limit settings, validates against quotas.
  """
  def set_organization_setting_with_user(org, user, setting_name, value) do
    # Ensure configuration exists
    config = get_or_create_configuration("Organization", org.id, "organization")
    schema_module = get_schema_module(config)

    # Check if setting is super_admin_only
    if Schema.super_admin_setting?(schema_module, setting_name) do
      if user && user.global_admin do
        # Super admin can set quota settings
        do_set_organization_setting(config, schema_module, org, setting_name, value)
      else
        {:error, "Only super admins can modify quota settings"}
      end
    else
      # Regular setting
      do_set_organization_setting(config, schema_module, org, setting_name, value)
    end
  end

  defp do_set_organization_setting(config, schema_module, org, setting_name, value) do
    # Special handling for validation that requires org context
    validation_result =
      cond do
        setting_name == :email_link_domain and schema_module == Schemas.Organization ->
          Schemas.Organization.validate_email_link_domain(org, value)

        setting_name in [:auth_rate_limit, :oauth_rate_limit, :saml_rate_limit, :api_rate_limit] and
            schema_module == Schemas.Organization ->
          Schemas.Organization.validate_rate_limit_with_quota(org, setting_name, value)

        true ->
          schema_module.validate_value(setting_name, value)
      end

    case validation_result do
      {:ok, validated_value} ->
        string_value = Schema.to_string_value(validated_value)

        # Encrypt if the setting is marked as encrypted
        final_value = maybe_encrypt_value(schema_module, setting_name, string_value)

        upsert_configuration_value(config, setting_name, final_value)

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Private functions

  defp get_schema_module(nil), do: Schemas.Global
  defp get_schema_module(%Configuration{schema_name: "global"}), do: Schemas.Global
  defp get_schema_module(%Configuration{schema_name: "organization"}), do: Schemas.Organization

  defp get_schema_module(%Configuration{schema_name: schema_name}) do
    raise "Unknown schema: #{schema_name}"
  end

  defp upsert_configuration_value(config, setting_name, value) do
    setting_name_str = to_string(setting_name)

    existing =
      config.configuration_values
      |> Enum.find(&(&1.setting_name == setting_name_str))

    result =
      if existing do
        existing
        |> ConfigurationValue.changeset(%{value: value})
        |> Repo.update()
      else
        %ConfigurationValue{}
        |> ConfigurationValue.changeset(%{
          configuration_id: config.id,
          setting_name: setting_name_str,
          value: value
        })
        |> Repo.insert()
      end

    # Invalidate cache on successful update
    case result do
      {:ok, _} ->
        Authify.Configurations.Cache.invalidate(
          config.configurable_type,
          config.configurable_id,
          setting_name
        )

      _ ->
        :ok
    end

    result
  end

  # Encryption helpers

  defp maybe_encrypt_value(schema_module, setting_name, value) do
    setting = Schema.get_setting(schema_module, setting_name)

    if setting && Map.get(setting, :encrypted, false) && value != nil && value != "" do
      Authify.Encryption.encrypt(value)
    else
      value
    end
  end

  defp maybe_decrypt_value(schema_module, setting_name, value) do
    setting = Schema.get_setting(schema_module, setting_name)

    if setting && Map.get(setting, :encrypted, false) && value != nil && value != "" do
      case Authify.Encryption.decrypt(value) do
        {:ok, decrypted} -> decrypted
        {:error, _} -> value
      end
    else
      value
    end
  end
end
