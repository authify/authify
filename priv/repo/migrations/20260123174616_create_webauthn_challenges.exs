defmodule Authify.Repo.Migrations.CreateWebauthnChallenges do
  use Ecto.Migration

  def change do
    create table(:webauthn_challenges) do
      add :user_id, references(:users, on_delete: :delete_all), null: false
      # Base64URL-encoded random challenge (32 bytes = 43 chars in base64url)
      add :challenge, :string, size: 255, null: false
      # "registration" or "authentication"
      add :challenge_type, :string, null: false
      # Challenges expire after 5 minutes
      add :expires_at, :utc_datetime, null: false
      # Set when challenge is successfully consumed
      add :consumed_at, :utc_datetime
      add :ip_address, :string
      add :user_agent, :text

      timestamps(type: :utc_datetime)
    end

    create index(:webauthn_challenges, [:challenge])
    create index(:webauthn_challenges, [:user_id])
    create index(:webauthn_challenges, [:expires_at])
    create index(:webauthn_challenges, [:consumed_at])
  end
end
