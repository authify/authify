defmodule Authify.Repo.Migrations.AddProfileFieldsToUsers do
  use Ecto.Migration

  def change do
    alter table(:users) do
      add :avatar_url, :string
      add :locale, :string
      add :zoneinfo, :string
      add :phone_number, :string
      add :phone_number_verified, :boolean, default: false, null: false
      add :website, :string
      add :team, :string
      add :title, :string
    end
  end
end
