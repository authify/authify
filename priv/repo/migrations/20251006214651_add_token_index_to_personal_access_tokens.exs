defmodule Authify.Repo.Migrations.AddTokenIndexToPersonalAccessTokens do
  use Ecto.Migration

  def change do
    # Add index on token field for fast authentication lookups
    # Token is now hashed (SHA-256), so this index is on the hash value
    create index(:personal_access_tokens, [:token])
  end
end
