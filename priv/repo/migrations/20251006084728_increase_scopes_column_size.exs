defmodule Authify.Repo.Migrations.IncreaseScopesColumnSize do
  use Ecto.Migration

  def change do
    # Change scopes column from VARCHAR(255) to TEXT to support longer scope lists
    alter table(:access_tokens) do
      modify :scopes, :text, null: false
    end

    alter table(:refresh_tokens) do
      modify :scopes, :text, null: false
    end

    alter table(:authorization_codes) do
      modify :scopes, :text, null: false
    end
  end
end
