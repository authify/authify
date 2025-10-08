defmodule Authify.Repo.Migrations.CreateScopes do
  use Ecto.Migration

  def change do
    create table(:scopes) do
      add :scope, :string, null: false
      add :scopeable_type, :string, null: false
      add :scopeable_id, :bigint, null: false

      timestamps(type: :utc_datetime)
    end

    # Index for finding all scopes for a specific resource
    create index(:scopes, [:scopeable_type, :scopeable_id])

    # Index for finding all resources with a specific scope
    create index(:scopes, [:scope])

    # Ensure unique scopes per resource
    create unique_index(:scopes, [:scope, :scopeable_type, :scopeable_id],
             name: :scopes_scope_scopeable_type_scopeable_id_index
           )
  end
end
