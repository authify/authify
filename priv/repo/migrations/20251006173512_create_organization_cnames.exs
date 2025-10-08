defmodule Authify.Repo.Migrations.CreateOrganizationCnames do
  use Ecto.Migration

  def change do
    create table(:organization_cnames) do
      add :organization_id, references(:organizations, on_delete: :delete_all), null: false
      add :domain, :string, null: false
      add :verified, :boolean, default: false, null: false

      timestamps(type: :utc_datetime)
    end

    create index(:organization_cnames, [:organization_id])
    create unique_index(:organization_cnames, [:domain])
  end
end
