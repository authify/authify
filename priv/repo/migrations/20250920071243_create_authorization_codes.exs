defmodule Authify.Repo.Migrations.CreateAuthorizationCodes do
  use Ecto.Migration

  def change do
    create table(:authorization_codes) do
      add :code, :string, null: false
      add :redirect_uri, :string, null: false
      add :scopes, :string, null: false
      add :expires_at, :utc_datetime, null: false
      add :used_at, :utc_datetime
      add :application_id, references(:applications, on_delete: :delete_all), null: false
      add :user_id, references(:users, on_delete: :delete_all), null: false

      timestamps(type: :utc_datetime)
    end

    create unique_index(:authorization_codes, [:code])
    create index(:authorization_codes, [:application_id])
    create index(:authorization_codes, [:user_id])
    create index(:authorization_codes, [:expires_at])
  end
end
