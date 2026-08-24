defmodule Authify.Repo.Migrations.SeedTenantBaseDomain do
  use Ecto.Migration
  import Ecto.Query

  # Seed a default tenant_base_domain for the test environment only. This
  # eliminates the deadlock (1213) that occurred when many async tests each
  # wrote tenant_base_domain in their setup — concurrent INSERTs to the same
  # unique key gap-locked in MySQL. By pre-seeding the row, tests inherit it
  # from the migrated DB state and never need to write it.
  #
  # In production, this migration is a no-op — the guided setup process
  # provides the tenant_base_domain, and we don't want to pollute it with
  # a test-only default.
  @test_domain "authify.test"

  def up do
    unless Mix.env() == :test do
      :ok
    else
      seed_tenant_base_domain()
    end
  end

  defp seed_tenant_base_domain do
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
          now = DateTime.truncate(DateTime.utc_now(), :second)

          repo().insert_all("configuration_values", [
            %{
              configuration_id: config_id,
              setting_name: "tenant_base_domain",
              value: @test_domain,
              inserted_at: now,
              updated_at: now
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
