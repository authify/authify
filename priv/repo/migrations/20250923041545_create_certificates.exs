defmodule Authify.Repo.Migrations.CreateCertificates do
  use Ecto.Migration

  def change do
    create table(:certificates) do
      add :name, :string, null: false
      add :usage, :string, null: false
      add :private_key, :text, null: false
      add :certificate, :text, null: false
      add :expires_at, :utc_datetime, null: false
      add :is_active, :boolean, default: false, null: false
      add :organization_id, references(:organizations, on_delete: :delete_all), null: false

      timestamps(type: :utc_datetime)
    end

    create unique_index(:certificates, [:name, :organization_id],
             name: :certificates_name_organization_id_index
           )

    create index(:certificates, [:organization_id])
    create index(:certificates, [:usage])
    create index(:certificates, [:is_active])
    create index(:certificates, [:expires_at])
  end
end
