defmodule Authify.Repo.Migrations.CreateGlobalOrganization do
  use Ecto.Migration

  def up do
    # Create the global organization for system administration
    execute """
    INSERT INTO organizations (name, slug, active, inserted_at, updated_at)
    VALUES ('Authify Global', 'authify-global', true, NOW(), NOW())
    """
  end

  def down do
    execute "DELETE FROM organizations WHERE slug = 'authify-global'"
  end
end
