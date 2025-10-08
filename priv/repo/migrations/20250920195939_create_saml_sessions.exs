defmodule Authify.Repo.Migrations.CreateSamlSessions do
  use Ecto.Migration

  def change do
    create table(:saml_sessions) do
      add :session_id, :string, null: false
      add :subject_id, :string, null: false
      # Original SAML request ID for response correlation
      add :request_id, :string
      # Optional RelayState parameter
      add :relay_state, :string
      add :issued_at, :utc_datetime, null: false
      add :expires_at, :utc_datetime, null: false
      add :user_id, references(:users, on_delete: :delete_all), null: true

      add :service_provider_id, references(:service_providers, on_delete: :delete_all),
        null: false

      timestamps(type: :utc_datetime)
    end

    create unique_index(:saml_sessions, [:session_id])
    create index(:saml_sessions, [:user_id])
    create index(:saml_sessions, [:service_provider_id])
    create index(:saml_sessions, [:expires_at])
  end
end
