defmodule Authify.Repo.Migrations.AddHomepageUrlToApplications do
  use Ecto.Migration

  def change do
    alter table(:applications) do
      add :homepage_url, :string
    end
  end
end
