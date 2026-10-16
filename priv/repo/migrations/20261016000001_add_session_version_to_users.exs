defmodule Authify.Repo.Migrations.AddSessionVersionToUsers do
  use Ecto.Migration

  def change do
    alter table(:users) do
      # Monotonically increasing counter embedded in session tokens. Bumping it
      # invalidates every previously issued token for the user, which lets an
      # admin force a password reset to immediately revoke active sessions.
      add :session_version, :integer, null: false, default: 0
    end
  end
end
