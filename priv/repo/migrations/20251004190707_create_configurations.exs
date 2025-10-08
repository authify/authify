defmodule Authify.Repo.Migrations.CreateConfigurations do
  use Ecto.Migration

  def change do
    create table(:configurations) do
      add :configurable_type, :string, null: false
      add :configurable_id, :bigint, null: false
      add :schema_name, :string, null: false

      timestamps(type: :utc_datetime)
    end

    create unique_index(:configurations, [:configurable_type, :configurable_id])
    create index(:configurations, [:schema_name])

    create table(:configuration_values) do
      add :configuration_id, references(:configurations, on_delete: :delete_all), null: false
      add :setting_name, :string, null: false
      add :value, :text

      timestamps(type: :utc_datetime)
    end

    create index(:configuration_values, [:configuration_id])
    create unique_index(:configuration_values, [:configuration_id, :setting_name])
  end
end
