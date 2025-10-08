defmodule Authify.Repo.Migrations.CreateInvitations do
  use Ecto.Migration

  def change do
    create table(:invitations) do
      add :email, :string, null: false
      add :token, :string, null: false
      add :role, :string, default: "user", null: false
      add :expires_at, :utc_datetime, null: false
      add :accepted_at, :utc_datetime
      add :organization_id, references(:organizations, on_delete: :delete_all), null: false
      add :invited_by_id, references(:users, on_delete: :delete_all), null: false

      timestamps(type: :utc_datetime)
    end

    create unique_index(:invitations, [:token])
    create unique_index(:invitations, [:email, :organization_id])
    create index(:invitations, [:organization_id])
    create index(:invitations, [:invited_by_id])
    create index(:invitations, [:expires_at])
  end
end
