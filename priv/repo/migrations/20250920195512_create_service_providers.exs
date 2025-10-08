defmodule Authify.Repo.Migrations.CreateServiceProviders do
  use Ecto.Migration

  def change do
    create table(:service_providers) do
      add :name, :string, null: false
      add :entity_id, :string, null: false
      add :acs_url, :string, null: false
      add :sls_url, :string
      add :certificate, :text
      add :metadata, :text
      # JSON field for custom attribute mapping
      add :attribute_mapping, :text
      add :sign_requests, :boolean, default: false, null: false
      add :sign_assertions, :boolean, default: true, null: false
      add :encrypt_assertions, :boolean, default: false, null: false
      add :is_active, :boolean, default: false, null: false
      add :organization_id, references(:organizations, on_delete: :delete_all), null: false

      timestamps(type: :utc_datetime)
    end

    create unique_index(:service_providers, [:entity_id, :organization_id])
    create index(:service_providers, [:organization_id])
    create index(:service_providers, [:is_active])
  end
end
