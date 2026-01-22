defmodule Authify.Repo.Migrations.CreateScimExternalIds do
  use Ecto.Migration

  def change do
    create table(:scim_external_ids) do
      add :scim_client_id, references(:scim_clients, on_delete: :delete_all), null: false
      # "User" or "Group"
      add :resource_type, :string, null: false
      # ID in Authify
      add :resource_id, :integer, null: false
      # ID in remote system
      add :external_id, :string, null: false

      timestamps(type: :utc_datetime)
    end

    create unique_index(
             :scim_external_ids,
             [:scim_client_id, :resource_type, :resource_id],
             name: :scim_external_ids_unique
           )

    create index(:scim_external_ids, [:resource_type, :resource_id])
  end
end
