defmodule Authify.Repo.Migrations.CreateAccessTokens do
  use Ecto.Migration

  def change do
    create table(:access_tokens) do
      add :token, :string, null: false
      add :scopes, :string, null: false
      add :expires_at, :utc_datetime, null: false
      add :revoked_at, :utc_datetime
      add :application_id, references(:applications, on_delete: :delete_all), null: false
      add :user_id, references(:users, on_delete: :delete_all), null: true

      timestamps(type: :utc_datetime)
    end

    create unique_index(:access_tokens, [:token])
    create index(:access_tokens, [:application_id])
    create index(:access_tokens, [:user_id])
    create index(:access_tokens, [:expires_at])
    create index(:access_tokens, [:revoked_at])
  end
end
