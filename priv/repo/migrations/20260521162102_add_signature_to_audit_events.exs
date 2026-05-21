defmodule Authify.Repo.Migrations.AddSignatureToAuditEvents do
  use Ecto.Migration

  def change do
    alter table(:audit_events) do
      add :signature, :text, null: true
      add :signing_certificate_id, references(:certificates, on_delete: :nothing), null: true
    end

    create index(:audit_events, [:signing_certificate_id])
  end
end
