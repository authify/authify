defmodule AuthifyWeb.Audit.Configuration do
  @moduledoc """
  Audit logging for configuration change events.
  """

  alias Authify.Configurations.Schemas.Organization
  alias AuthifyWeb.Audit.Base

  @sensitive_fields MapSet.new(~w(smtp_password))

  @doc """
  Returns the set of rate-limit setting names, including both override and quota
  settings.

  Derived from the organization configuration schema so the audit tagging cannot
  drift behind newly added rate-limit scopes.
  """
  def rate_limit_fields do
    Organization.rate_limit_settings()
    |> Enum.flat_map(fn %{name: name} ->
      [to_string(name), to_string(Organization.quota_name_for_setting(name))]
    end)
    |> MapSet.new()
  end

  @doc """
  Logs a configuration change event, summarizing differences between settings.
  """
  def log_configuration_update(conn, schema_name, old_settings, new_settings, opts \\ []) do
    rate_limit_field_set = Base.kwargs_to_set(opts[:rate_limit_fields], rate_limit_fields())
    sensitive_fields = Base.kwargs_to_set(opts[:sensitive_fields], @sensitive_fields)

    changes = Base.diff_settings(old_settings, new_settings, sensitive_fields)

    if changes != [] do
      rate_limit_changes =
        Enum.filter(changes, fn %{"field" => field} ->
          MapSet.member?(rate_limit_field_set, field)
        end)

      metadata =
        %{
          "schema" => schema_name,
          "organization_slug" => conn.assigns.current_organization.slug,
          "changes" => changes
        }
        |> Base.maybe_put("rate_limit_changes", rate_limit_changes)
        |> Base.maybe_merge(opts[:extra_metadata])

      Base.log_event_async(
        conn,
        :settings_updated,
        opts[:resource_type] || "configuration",
        opts[:resource_id] || conn.assigns.current_organization.id,
        opts[:outcome] || "success",
        metadata
      )
    else
      :noop
    end
  end

  @doc """
  Logs a failed configuration update attempt with error details.
  """
  def log_configuration_update_failure(conn, schema_name, errors, opts \\ []) do
    metadata =
      %{
        "schema" => schema_name,
        "organization_slug" => conn.assigns.current_organization.slug,
        "errors" => List.wrap(errors)
      }
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      :settings_updated,
      opts[:resource_type] || "configuration",
      opts[:resource_id] || conn.assigns.current_organization.id,
      "failure",
      metadata
    )
  end
end
