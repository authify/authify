defmodule Authify.Configurations.ConfigurationValue do
  @moduledoc """
  Schema for individual configuration setting values. Each value belongs to a
  Configuration and stores the setting name and value as strings. Values are
  encrypted if marked as such in the schema definition.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias Authify.Configurations.Configuration

  @derive {Jason.Encoder, except: [:__meta__, :configuration]}

  schema "configuration_values" do
    field :setting_name, :string
    field :value, :string

    belongs_to :configuration, Configuration

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(configuration_value, attrs) do
    configuration_value
    |> cast(attrs, [:configuration_id, :setting_name, :value])
    |> validate_required([:configuration_id, :setting_name])
    |> unique_constraint([:configuration_id, :setting_name])
  end
end
