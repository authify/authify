defmodule Authify.Repo.Migrations.AddTotpToUsers do
  use Ecto.Migration

  def change do
    alter table(:users) do
      # Encrypted TOTP secret (Base32-encoded secret, encrypted with AES-256-GCM)
      add :totp_secret, :text

      # When TOTP was enabled by the user
      add :totp_enabled_at, :utc_datetime

      # Backup codes (JSON array of bcrypt hashes)
      add :totp_backup_codes, :text

      # When backup codes were last regenerated
      add :totp_backup_codes_generated_at, :utc_datetime
    end
  end
end
