defmodule Authify.Repo.Migrations.AddNonceToAuthorizationCodes do
  use Ecto.Migration

  def change do
    alter table(:authorization_codes) do
      add :nonce, :string, size: 2048
    end
  end
end
