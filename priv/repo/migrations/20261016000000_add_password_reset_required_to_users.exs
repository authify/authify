defmodule Authify.Repo.Migrations.AddPasswordResetRequiredToUsers do
  use Ecto.Migration

  def change do
    alter table(:users) do
      # When true, the user must change their password before continuing.
      # Set by admins via Accounts.force_password_reset/1 and cleared on the
      # next successful password change.
      add :password_reset_required, :boolean, null: false, default: false
    end
  end
end
