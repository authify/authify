defmodule Authify.Repo.Migrations.AddDeletedAtToCertificates do
  use Ecto.Migration

  def change do
    alter table(:certificates) do
      add :deleted_at, :utc_datetime, null: true
    end

    create index(:certificates, [:deleted_at])
  end
end
