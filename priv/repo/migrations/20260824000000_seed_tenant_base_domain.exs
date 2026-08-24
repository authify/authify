defmodule Authify.Repo.Migrations.SeedTenantBaseDomain do
  use Ecto.Migration
  import Ecto.Query

  @default_domain "authify.test"

  def up do
    global_org_id =
      repo().one(
        from(o in "organizations",
          where: o.slug == "authify-global",
          select: o.id
        )
      )

    if global_org_id do
      config_id =
        repo().one(
          from(c in "configurations",
            where:
              c.configurable_type == "Organization" and
                c.configurable_id == ^global_org_id,
            select: c.id
          )
        )

      if config_id do
        # Only insert if the setting doesn't already exist
        existing =
          repo().one(
            from(cv in "configuration_values",
              where:
                cv.configuration_id == ^config_id and
                  cv.setting_name == "tenant_base_domain",
              select: cv.id
            )
          )

        unless existing do
          repo().insert_all("configuration_values", [
            %{
              configuration_id: config_id,
              setting_name: "tenant_base_domain",
              value: @default_domain,
              inserted_at: DateTime.truncate(DateTime.utc_now(), :second),
              updated_at: DateTime.truncate(DateTime.utc_now(), :second)
            }
          ])
        end
      end
    end
  end

  def down do
    :ok
  end
end
