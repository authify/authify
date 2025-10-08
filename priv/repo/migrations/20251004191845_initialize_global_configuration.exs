defmodule Authify.Repo.Migrations.InitializeGlobalConfiguration do
  use Ecto.Migration
  import Ecto.Query

  def up do
    # Get the global organization ID
    global_org_id =
      repo().one(
        from(o in "organizations",
          where: o.slug == "authify-global",
          select: o.id
        )
      )

    if global_org_id do
      # Create configuration for global organization
      repo().insert_all("configurations", [
        %{
          configurable_type: "Organization",
          configurable_id: global_org_id,
          schema_name: "global",
          inserted_at: DateTime.truncate(DateTime.utc_now(), :second),
          updated_at: DateTime.truncate(DateTime.utc_now(), :second)
        }
      ])

      # Get the configuration ID
      config_id =
        repo().one(
          from(c in "configurations",
            where: c.configurable_type == "Organization" and c.configurable_id == ^global_org_id,
            select: c.id
          )
        )

      if config_id do
        # Initialize default settings
        repo().insert_all("configuration_values", [
          %{
            configuration_id: config_id,
            setting_name: "allow_organization_registration",
            value: "false",
            inserted_at: DateTime.truncate(DateTime.utc_now(), :second),
            updated_at: DateTime.truncate(DateTime.utc_now(), :second)
          },
          %{
            configuration_id: config_id,
            setting_name: "site_name",
            value: "Authify",
            inserted_at: DateTime.truncate(DateTime.utc_now(), :second),
            updated_at: DateTime.truncate(DateTime.utc_now(), :second)
          }
        ])
      end
    end
  end

  def down do
    # Get the global organization ID
    global_org_id =
      repo().one(
        from(o in "organizations",
          where: o.slug == "authify-global",
          select: o.id
        )
      )

    if global_org_id do
      repo().delete_all(
        from(c in "configurations",
          where: c.configurable_type == "Organization" and c.configurable_id == ^global_org_id
        )
      )
    end
  end
end
