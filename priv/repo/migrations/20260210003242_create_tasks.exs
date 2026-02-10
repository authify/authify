defmodule Authify.Repo.Migrations.CreateTasks do
  use Ecto.Migration

  def change do
    create table(:tasks, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :type, :string, null: false
      add :action, :string, null: false
      add :params, :map, null: false
      add :status, :string, null: false, default: "pending"
      add :priority, :integer, default: 0, null: false
      add :max_retries, :integer, default: 3, null: false
      add :retry_count, :integer, default: 0, null: false
      add :timeout_seconds, :integer
      add :scheduled_at, :utc_datetime
      add :started_at, :utc_datetime
      add :completed_at, :utc_datetime
      add :failed_at, :utc_datetime
      add :expires_at, :utc_datetime
      add :results, :map
      add :errors, :map
      add :correlation_id, :string
      add :metadata, :map
      add :organization_id, references(:organizations, on_delete: :nothing)
      add :parent_id, references(:tasks, type: :binary_id, on_delete: :nothing)

      timestamps(type: :utc_datetime)
    end

    # Composite index for exclusivity checks (Phase 1 filtering)
    create index(:tasks, [:type, :action, :organization_id, :status],
             name: :tasks_exclusivity_idx
           )

    # Individual indexes for lookups
    create index(:tasks, [:organization_id])
    create index(:tasks, [:parent_id])
    create index(:tasks, [:correlation_id])
    create index(:tasks, [:status])
    create index(:tasks, [:scheduled_at])
  end
end
