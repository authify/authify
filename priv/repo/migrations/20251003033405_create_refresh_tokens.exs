defmodule Authify.Repo.Migrations.CreateRefreshTokens do
  use Ecto.Migration

  def change do
    create table(:refresh_tokens) do
      add :token, :string, null: false
      add :scopes, :string, null: false
      add :expires_at, :utc_datetime, null: false
      add :revoked_at, :utc_datetime
      add :application_id, references(:applications, on_delete: :delete_all), null: false
      add :user_id, references(:users, on_delete: :delete_all), null: false
      add :access_token_id, references(:access_tokens, on_delete: :nilify_all)

      timestamps(type: :utc_datetime)
    end

    create unique_index(:refresh_tokens, [:token])
    create index(:refresh_tokens, [:application_id])
    create index(:refresh_tokens, [:user_id])
    create index(:refresh_tokens, [:expires_at])
  end
end
