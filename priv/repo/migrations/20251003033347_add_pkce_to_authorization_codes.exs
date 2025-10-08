defmodule Authify.Repo.Migrations.AddPkceToAuthorizationCodes do
  use Ecto.Migration

  def change do
    alter table(:authorization_codes) do
      add :code_challenge, :string
      add :code_challenge_method, :string
    end
  end
end
