defmodule Authify.Repo.Migrations.CreateApplicationGroupMembers do
  use Ecto.Migration

  def change do
    create table(:application_group_members) do
      add :application_id, :integer, null: false
      add :application_type, :string, null: false

      add :application_group_id, references(:application_groups, on_delete: :delete_all),
        null: false

      timestamps(type: :utc_datetime)
    end

    create index(:application_group_members, [:application_group_id])
    create index(:application_group_members, [:application_id, :application_type])

    create unique_index(
             :application_group_members,
             [:application_id, :application_type, :application_group_id],
             name: :app_group_members_unique_app_idx
           )
  end
end
