defmodule Authify.Repo.Migrations.CreateUserEmails do
  use Ecto.Migration

  def up do
    # Create user_emails table
    create table(:user_emails) do
      add :user_id, references(:users, on_delete: :delete_all), null: false
      add :value, :string, null: false
      add :type, :string, default: "work"
      add :primary, :boolean, default: false, null: false
      add :display, :string
      add :verified_at, :utc_datetime
      add :verification_token, :string
      add :verification_expires_at, :utc_datetime

      timestamps()
    end

    create index(:user_emails, [:user_id])
    # Globally unique emails
    create unique_index(:user_emails, [:value])
    # Covering index for fast login queries (email -> user_id without table lookup)
    create index(:user_emails, [:value, :user_id, :primary])
    # Note: MySQL doesn't support partial unique indexes
    # Primary email constraint is enforced at application level via UserEmail.changeset

    # Migrate existing emails from users table to user_emails
    execute """
    INSERT INTO user_emails (user_id, value, type, `primary`, verified_at, verification_token, verification_expires_at, inserted_at, updated_at)
    SELECT id, email, 'work', 1, email_confirmed_at, email_verification_token, email_verification_expires_at, NOW(), NOW()
    FROM users
    WHERE email IS NOT NULL
    """

    # Drop old email columns from users table
    alter table(:users) do
      remove :email
      remove :email_confirmed_at
      remove :email_verification_token
      remove :email_verification_expires_at
    end
  end

  def down do
    # Add email columns back to users
    alter table(:users) do
      add :email, :string
      add :email_confirmed_at, :utc_datetime
      add :email_verification_token, :string
      add :email_verification_expires_at, :utc_datetime
    end

    # Migrate primary emails back to users table
    execute """
    UPDATE users u
    INNER JOIN user_emails ue ON u.id = ue.user_id
    SET u.email = ue.value,
        u.email_confirmed_at = ue.verified_at,
        u.email_verification_token = ue.verification_token,
        u.email_verification_expires_at = ue.verification_expires_at
    WHERE ue.primary = 1
    """

    # Drop user_emails table
    drop table(:user_emails)
  end
end
