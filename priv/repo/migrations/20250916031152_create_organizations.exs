defmodule Authify.Repo.Migrations.CreateOrganizations do
  use Ecto.Migration

  def change do
    create table(:organizations) do
      add :name, :string, null: false
      add :slug, :string, null: false
      add :active, :boolean, default: true

      timestamps(type: :utc_datetime)
    end

    create unique_index(:organizations, [:slug])
  end
end
