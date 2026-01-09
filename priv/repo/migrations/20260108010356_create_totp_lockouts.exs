defmodule Authify.Repo.Migrations.CreateTotpLockouts do
  use Ecto.Migration

  def change do
    create table(:totp_lockouts) do
      add :user_id, references(:users, on_delete: :delete_all), null: false
      add :locked_at, :utc_datetime, null: false
      add :locked_until, :utc_datetime, null: false
      add :failed_attempts, :integer, default: 0
      add :locked_by_ip, :string
      add :unlocked_at, :utc_datetime
      add :unlocked_by_admin_id, references(:users, on_delete: :nilify_all)

      timestamps(type: :utc_datetime)
    end

    create index(:totp_lockouts, [:user_id])
    create index(:totp_lockouts, [:locked_until])
  end
end
