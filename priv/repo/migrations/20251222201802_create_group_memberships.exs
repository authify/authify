defmodule Authify.Repo.Migrations.CreateGroupMemberships do
  use Ecto.Migration

  def change do
    create table(:group_memberships) do
      add :user_id, references(:users, on_delete: :delete_all), null: false
      add :group_id, references(:groups, on_delete: :delete_all), null: false

      timestamps(type: :utc_datetime)
    end

    create index(:group_memberships, [:user_id])
    create index(:group_memberships, [:group_id])
    create unique_index(:group_memberships, [:user_id, :group_id])
  end
end
