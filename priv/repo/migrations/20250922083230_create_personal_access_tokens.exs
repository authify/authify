defmodule Authify.Repo.Migrations.CreatePersonalAccessTokens do
  use Ecto.Migration

  def change do
    create table(:personal_access_tokens) do
      add :name, :string
      add :description, :text
      add :token, :string
      add :last_used_at, :utc_datetime
      add :expires_at, :utc_datetime
      add :is_active, :boolean, default: false, null: false
      add :user_id, references(:users, on_delete: :nothing)
      add :organization_id, references(:organizations, on_delete: :nothing)

      timestamps(type: :utc_datetime)
    end

    create index(:personal_access_tokens, [:user_id])
    create index(:personal_access_tokens, [:organization_id])
  end
end
