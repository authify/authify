defmodule Authify.Repo.Migrations.AddGrantTypesToApplications do
  use Ecto.Migration

  def change do
    alter table(:applications) do
      # Grant types: authorization_code, refresh_token, client_credentials
      add :grant_types, :string, default: "authorization_code refresh_token"
      # Client type: confidential (web), public (spa, native)
      add :client_type, :string, default: "confidential"
      # Require PKCE for this application
      add :require_pkce, :boolean, default: false
    end
  end
end
