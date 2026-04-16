defmodule Authify.Repo.Migrations.AddNonceToRefreshTokens do
  use Ecto.Migration

  def change do
    alter table(:refresh_tokens) do
      add :nonce, :string, size: 2048
    end
  end
end
