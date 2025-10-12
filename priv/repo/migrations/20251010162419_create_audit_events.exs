defmodule Authify.Repo.Migrations.CreateAuditEvents do
  use Ecto.Migration

  def change do
    create table(:audit_events) do
      add :event_type, :string, null: false, size: 50
      add :actor_type, :string, null: false, size: 20
      add :actor_id, :integer
      add :actor_name, :string, size: 255
      add :resource_type, :string, size: 100
      add :resource_id, :integer
      add :ip_address, :string, size: 45
      add :user_agent, :text
      add :outcome, :string, null: false, size: 20
      add :metadata, :json

      add :organization_id, references(:organizations, on_delete: :delete_all), null: false

      add :inserted_at, :utc_datetime, null: false
    end

    create index(:audit_events, [:organization_id])
    create index(:audit_events, [:actor_type, :actor_id])
    create index(:audit_events, [:event_type])
    create index(:audit_events, [:actor_type])
    create index(:audit_events, [:inserted_at])
    create index(:audit_events, [:organization_id, :event_type])
    create index(:audit_events, [:organization_id, :inserted_at])
    create index(:audit_events, [:resource_type, :resource_id])
  end
end
