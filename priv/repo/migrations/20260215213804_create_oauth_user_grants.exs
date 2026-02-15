defmodule Authify.Repo.Migrations.CreateOauthUserGrants do
  use Ecto.Migration

  def change do
    create table(:oauth_user_grants) do
      add :user_id, references(:users, on_delete: :delete_all), null: false
      add :application_id, references(:applications, on_delete: :delete_all), null: false
      add :scopes, :string, null: false
      add :revoked_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create unique_index(:oauth_user_grants, [:user_id, :application_id],
             name: :oauth_user_grants_user_app_unique
           )

    create index(:oauth_user_grants, [:user_id])
    create index(:oauth_user_grants, [:application_id])
    create index(:oauth_user_grants, [:revoked_at])
  end
end
