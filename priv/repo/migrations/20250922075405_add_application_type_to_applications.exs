defmodule Authify.Repo.Migrations.AddApplicationTypeToApplications do
  use Ecto.Migration

  def change do
    alter table(:applications) do
      add :application_type, :string, default: "oauth2_app", null: false
    end

    create index(:applications, [:application_type])
  end
end
