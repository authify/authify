defmodule Authify.Repo.Migrations.CreateUserApplicationGroups do
  use Ecto.Migration

  def change do
    create table(:user_application_groups) do
      add :user_id, references(:users, on_delete: :delete_all), null: false

      add :application_group_id, references(:application_groups, on_delete: :delete_all),
        null: false

      timestamps(type: :utc_datetime)
    end

    create index(:user_application_groups, [:user_id])
    create index(:user_application_groups, [:application_group_id])
    create unique_index(:user_application_groups, [:user_id, :application_group_id])
  end
end
