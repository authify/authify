defmodule Authify.Repo.Migrations.CreateSamlCertificates do
  use Ecto.Migration

  def change do
    create table(:saml_certificates) do
      add :name, :string, null: false
      # "signing" or "encryption"
      add :purpose, :string, null: false
      add :certificate, :text, null: false
      add :private_key, :text, null: false
      add :is_active, :boolean, default: true, null: false
      add :expires_at, :utc_datetime, null: false
      add :organization_id, references(:organizations, on_delete: :delete_all), null: false

      timestamps(type: :utc_datetime)
    end

    create index(:saml_certificates, [:organization_id])
    create index(:saml_certificates, [:purpose, :is_active])
    # MySQL doesn't support WHERE in indexes, we'll handle uniqueness in application code
    create index(:saml_certificates, [:organization_id, :purpose, :is_active],
             name: :one_active_cert_per_org_purpose
           )
  end
end
