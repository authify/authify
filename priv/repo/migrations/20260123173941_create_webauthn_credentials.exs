defmodule Authify.Repo.Migrations.CreateWebauthnCredentials do
  use Ecto.Migration

  def change do
    create table(:webauthn_credentials) do
      add :user_id, references(:users, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, on_delete: :delete_all), null: false
      # Base64URL-encoded credential ID (max 512 chars, typical is 22-86)
      add :credential_id, :string, size: 512, null: false
      # Encrypted public key (COSE format)
      add :public_key, :binary, null: false
      # Counter for detecting cloned credentials
      add :sign_count, :integer, default: 0, null: false
      # "platform" (Touch ID, Face ID) or "roaming" (YubiKey, etc.)
      add :credential_type, :string
      # JSON array of transport types: ["usb", "nfc", "ble", "internal"]
      add :transports, :text
      # Authenticator AAGUID
      add :aaguid, :binary
      # User-friendly name (e.g., "My YubiKey 5C")
      add :name, :string
      add :last_used_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create unique_index(:webauthn_credentials, [:credential_id])
    create index(:webauthn_credentials, [:user_id])
    create index(:webauthn_credentials, [:organization_id])
  end
end
