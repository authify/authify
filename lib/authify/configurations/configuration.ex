defmodule Authify.Configurations.Configuration do
  use Ecto.Schema
  import Ecto.Changeset

  alias Authify.Configurations.ConfigurationValue

  @derive {Jason.Encoder, except: [:__meta__, :configuration_values]}

  schema "configurations" do
    field :configurable_type, :string
    field :configurable_id, :integer
    field :schema_name, :string

    has_many :configuration_values, ConfigurationValue, on_delete: :delete_all

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(configuration, attrs) do
    configuration
    |> cast(attrs, [:configurable_type, :configurable_id, :schema_name])
    |> validate_required([:configurable_type, :configurable_id, :schema_name])
    |> unique_constraint([:configurable_type, :configurable_id])
  end
end
