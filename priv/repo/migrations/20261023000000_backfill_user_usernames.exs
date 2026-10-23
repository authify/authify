defmodule Authify.Repo.Migrations.BackfillUserUsernames do
  use Ecto.Migration

  @moduledoc """
  Backfills usernames for all users that are missing one, then makes the
  column NOT NULL.

  Authify historically allowed users without a username (several creation
  paths did not populate it), which caused the OIDC `preferred_username`
  claim — now backed by the real username — to have nothing valid to emit.
  This migration:

  1. Assigns every user with `username IS NULL` a sanitized,
     per-organization-unique username, seeded from the user's primary email.
     Uniqueness semantics match `Authify.Accounts.User.generate_unique_username/3`.
  2. Adds a `NOT NULL` constraint on `users.username` so future creation paths
     cannot regress. The existing unique index on
     `(username, organization_id)` is preserved.

  The per-row logic lives in `Authify.Accounts.backfill_missing_usernames/0`
  so it can be exercised by tests.
  """

  alias Authify.Accounts

  def up do
    {:ok, _updated} = Accounts.backfill_missing_usernames()

    alter table(:users) do
      modify :username, :string, null: false
    end
  end

  def down do
    # Generated usernames cannot be meaningfully reverted; only relax the
    # NOT NULL constraint.
    alter table(:users) do
      modify :username, :string, null: true
    end
  end
end
