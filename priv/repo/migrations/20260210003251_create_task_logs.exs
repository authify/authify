defmodule Authify.Repo.Migrations.CreateTaskLogs do
  use Ecto.Migration

  def change do
    create table(:task_logs, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :log_data, :text, null: false
      add :task_id, references(:tasks, type: :binary_id, on_delete: :delete_all), null: false

      timestamps(type: :utc_datetime)
    end

    create index(:task_logs, [:task_id])
  end
end
