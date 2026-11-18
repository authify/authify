defmodule Authify.Repo.Migrations.AddTokenFamilyToRefreshTokens do
  use Ecto.Migration

  @moduledoc """
  Adds token-family tracking to refresh tokens so that a *replayed* rotated
  token can be detected (reuse detection) and the whole family revoked.

  * `token_family_id` groups a token and all of its rotations. Existing rows are
    backfilled to a per-row singleton family so legacy tokens keep working and
    behave as their own family.
  * `revoke_reason` records *why* a token was revoked, which lets reuse detection
    distinguish a consumed-and-rotated token being replayed (theft) from a token
    that was deliberately revoked (password change, admin revocation).
  """

  def change do
    alter table(:refresh_tokens) do
      add :token_family_id, :string, null: true
      add :revoke_reason, :string, null: true
    end

    create index(:refresh_tokens, [:token_family_id])

    # Backfill legacy rows to a singleton family keyed by their own id.
    execute(
      "UPDATE refresh_tokens SET token_family_id = CAST(id AS CHAR) WHERE token_family_id IS NULL",
      "UPDATE refresh_tokens SET token_family_id = NULL"
    )
  end
end
