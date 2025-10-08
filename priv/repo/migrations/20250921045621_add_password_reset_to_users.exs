defmodule Authify.Repo.Migrations.AddPasswordResetToUsers do
  use Ecto.Migration

  def change do
    alter table(:users) do
      add :password_reset_token, :string
      add :password_reset_expires_at, :utc_datetime
    end

    create unique_index(:users, [:password_reset_token])
  end
end
