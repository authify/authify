defmodule Authify.Repo.Migrations.CreateScimClients do
  use Ecto.Migration

  def change do
    create table(:scim_clients) do
      add :name, :string, null: false
      add :description, :text
      add :base_url, :string, null: false
      # bearer, basic
      add :auth_type, :string, null: false, default: "bearer"
      # Encrypted bearer token or password
      add :auth_credential, :binary
      # For basic auth
      add :auth_username, :string
      # JSON mapping config
      add :attribute_mapping, :text
      add :is_active, :boolean, default: false
      add :sync_users, :boolean, default: true
      add :sync_groups, :boolean, default: true
      add :organization_id, references(:organizations, on_delete: :delete_all), null: false

      timestamps(type: :utc_datetime)
    end

    create index(:scim_clients, [:organization_id])

    create unique_index(:scim_clients, [:name, :organization_id],
             name: :scim_clients_name_org_unique
           )
  end
end
