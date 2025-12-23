defmodule Authify.Repo.Migrations.CreateGroupApplications do
  use Ecto.Migration

  def change do
    create table(:group_applications) do
      add :application_id, :integer, null: false
      add :application_type, :string, null: false
      add :group_id, references(:groups, on_delete: :delete_all), null: false

      timestamps(type: :utc_datetime)
    end

    create index(:group_applications, [:group_id])
    create index(:group_applications, [:application_id, :application_type])

    create unique_index(:group_applications, [:application_id, :application_type, :group_id],
             name: :group_apps_app_type_group_unique
           )
  end
end
