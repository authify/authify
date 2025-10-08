defmodule Authify.Configurations.Schema do
  @moduledoc """
  Behavior for configuration schemas.

  A configuration schema defines the settings available for a particular
  configurable type (e.g., global settings, organization settings).

  Each setting has:
  - name: unique identifier
  - description: human-readable description
  - value_type: :string, :boolean, :integer, :float
  - default_value: default if not set
  - required: whether the setting must have a value
  - validation_fn: optional function to validate the value
  - encrypted: whether the value should be encrypted at rest (default: false)
  """

  @type setting :: %{
          name: atom(),
          description: String.t(),
          value_type: :string | :boolean | :integer | :float,
          default_value: any(),
          required: boolean(),
          validation_fn: (any() -> {:ok, any()} | {:error, String.t()}) | nil,
          encrypted: boolean(),
          super_admin_only: boolean()
        }

  @callback schema_name() :: String.t()
  @callback settings() :: [setting()]
  @callback validate_value(setting_name :: atom(), value :: any()) ::
              {:ok, any()} | {:error, String.t()}

  @doc """
  Gets a setting definition by name.
  """
  def get_setting(schema_module, setting_name) do
    schema_module.settings()
    |> Enum.find(&(&1.name == setting_name))
  end

  @doc """
  Gets the default value for a setting.
  """
  def get_default(schema_module, setting_name) do
    case get_setting(schema_module, setting_name) do
      nil -> nil
      setting -> setting.default_value
    end
  end

  @doc """
  Casts a string value to the appropriate type.
  """
  def cast_value(_value_type, nil), do: {:ok, nil}

  def cast_value(:string, value) when is_binary(value), do: {:ok, value}

  def cast_value(:boolean, value) when is_binary(value) do
    case String.downcase(value) do
      "true" -> {:ok, true}
      "false" -> {:ok, false}
      "1" -> {:ok, true}
      "0" -> {:ok, false}
      _ -> {:error, "must be true or false"}
    end
  end

  def cast_value(:boolean, value) when is_boolean(value), do: {:ok, value}

  def cast_value(:integer, value) when is_binary(value) do
    case Integer.parse(value) do
      {int, ""} -> {:ok, int}
      _ -> {:error, "must be an integer"}
    end
  end

  def cast_value(:integer, value) when is_integer(value), do: {:ok, value}

  def cast_value(:float, value) when is_binary(value) do
    case Float.parse(value) do
      {float, ""} -> {:ok, float}
      _ -> {:error, "must be a number"}
    end
  end

  def cast_value(:float, value) when is_float(value), do: {:ok, value}
  def cast_value(:float, value) when is_integer(value), do: {:ok, value / 1}

  def cast_value(_type, _value), do: {:error, "invalid value type"}

  @doc """
  Converts a value to string for storage.
  """
  def to_string_value(nil), do: nil
  def to_string_value(value) when is_binary(value), do: value
  def to_string_value(true), do: "true"
  def to_string_value(false), do: "false"
  def to_string_value(value) when is_integer(value), do: Integer.to_string(value)
  def to_string_value(value) when is_float(value), do: Float.to_string(value)

  @doc """
  Checks if a setting is super admin only.

  Defaults to false if not explicitly set, meaning org admins can see and modify it.
  """
  def is_super_admin_setting?(schema_module, setting_name) do
    case get_setting(schema_module, setting_name) do
      nil -> false
      setting -> Map.get(setting, :super_admin_only, false)
    end
  end
end
