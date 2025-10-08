defmodule Authify.Repo.Migrations.CreateApplications do
  use Ecto.Migration

  def change do
    create table(:applications) do
      add :name, :string, null: false
      add :client_id, :string, null: false
      add :client_secret, :string, null: false
      add :redirect_uris, :text, null: false
      add :description, :text
      add :organization_id, references(:organizations, on_delete: :delete_all), null: false
      add :is_active, :boolean, default: true

      timestamps(type: :utc_datetime)
    end

    create unique_index(:applications, [:client_id])
    create index(:applications, [:organization_id])
    create index(:applications, [:organization_id, :is_active])
  end
end
