defmodule Authify.Repo.Migrations.CreateUsers do
  use Ecto.Migration

  def change do
    create table(:users) do
      add :email, :string, null: false
      add :hashed_password, :string, null: false
      add :first_name, :string
      add :last_name, :string
      add :username, :string
      add :organization_id, references(:organizations, on_delete: :delete_all)
      add :role, :string, default: "user", null: false
      add :active, :boolean, default: true
      add :email_confirmed_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create unique_index(:users, [:email])
    create unique_index(:users, [:username, :organization_id])
    create index(:users, [:organization_id])
    create index(:users, [:role])
    create index(:users, [:active])
  end
end
