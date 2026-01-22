defmodule Authify.Repo.Migrations.CreateScimSyncLogs do
  use Ecto.Migration

  def change do
    create table(:scim_sync_logs) do
      add :scim_client_id, references(:scim_clients, on_delete: :delete_all), null: false
      # "User" or "Group"
      add :resource_type, :string, null: false
      add :resource_id, :integer, null: false
      # "create", "update", "delete"
      add :operation, :string, null: false
      # "pending", "success", "failed"
      add :status, :string, null: false
      add :http_status, :integer
      add :request_body, :text
      add :response_body, :text
      add :error_message, :text
      add :retry_count, :integer, default: 0
      add :next_retry_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create index(:scim_sync_logs, [:scim_client_id])
    create index(:scim_sync_logs, [:status])
    create index(:scim_sync_logs, [:resource_type, :resource_id])
    create index(:scim_sync_logs, [:next_retry_at])
  end
end
