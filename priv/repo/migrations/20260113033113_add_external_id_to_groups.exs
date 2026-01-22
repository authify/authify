defmodule Authify.Repo.Migrations.AddExternalIdToGroups do
  use Ecto.Migration

  def change do
    alter table(:groups) do
      add :external_id, :string
      add :scim_created_at, :utc_datetime
      add :scim_updated_at, :utc_datetime
    end

    # External ID must be unique per organization (multi-tenant isolation)
    # MySQL allows multiple NULL values in unique indexes, so no WHERE clause needed
    create unique_index(:groups, [:external_id, :organization_id],
             name: :groups_external_id_organization_id_index
           )

    # Optimize SCIM filter queries
    create index(:groups, [:organization_id, :external_id])
  end
end
