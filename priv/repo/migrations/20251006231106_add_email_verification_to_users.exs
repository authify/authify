defmodule Authify.Repo.Migrations.AddEmailVerificationToUsers do
  use Ecto.Migration

  def change do
    alter table(:users) do
      add :email_verification_token, :string
      add :email_verification_expires_at, :utc_datetime
    end

    create unique_index(:users, [:email_verification_token])
  end
end
