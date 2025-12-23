defmodule Authify.Repo.Migrations.CreateGroups do
  use Ecto.Migration

  def change do
    create table(:groups) do
      add :name, :string, null: false
      add :description, :text
      add :is_active, :boolean, default: true, null: false
      add :organization_id, references(:organizations, on_delete: :delete_all), null: false

      timestamps(type: :utc_datetime)
    end

    create index(:groups, [:organization_id])
    create unique_index(:groups, [:name, :organization_id])
  end
end
