defmodule AuthifyWeb.API.OrganizationController do
  use AuthifyWeb.API.BaseController

  alias Authify.Configurations

  @doc """
  GET /{org_slug}/api/organization

  Get the current organization details.
  Requires organizations:read scope.
  """
  def show(conn, _params) do
    with :ok <- ensure_scope(conn, "organizations:read") do
      organization = conn.assigns.current_organization

      render_api_response(conn, organization,
        resource_type: "organization",
        exclude: [:settings]
      )
    else
      {:error, response} -> response
    end
  end

  @doc """
  GET /{org_slug}/api/organization/configuration

  Get the organization's configuration settings (Global schema for authify-global, Organization schema for others).
  Requires organizations:read scope.
  """
  def configuration(conn, _params) do
    with :ok <- ensure_scope(conn, "organizations:read") do
      organization = conn.assigns.current_organization
      user = conn.assigns.current_user

      # Determine schema based on organization
      schema_name =
        if organization.slug == "authify-global" do
          "global"
        else
          "organization"
        end

      all_settings = Configurations.get_all_settings("Organization", organization.id)

      # Filter quota settings based on user permissions
      settings = filter_settings_by_permission(schema_name, all_settings, user)

      configuration_data = %{
        id: organization.id,
        schema_name: schema_name,
        settings: settings,
        updated_at: NaiveDateTime.utc_now()
      }

      render_api_response(conn, configuration_data, resource_type: "configuration")
    else
      {:error, response} -> response
    end
  end

  @doc """
  PUT /{org_slug}/api/organization/configuration

  Update organization configuration settings.
  Requires organizations:write scope.
  """
  def update_configuration(conn, %{"settings" => settings_params}) do
    with :ok <- ensure_scope(conn, "organizations:write") do
      organization = conn.assigns.current_organization
      user = conn.assigns.current_user

      # Determine schema based on organization
      schema_name =
        if organization.slug == "authify-global" do
          "global"
        else
          "organization"
        end

      # Ensure configuration exists
      Configurations.get_or_create_configuration("Organization", organization.id, schema_name)

      # Update each setting
      results =
        Enum.map(settings_params, fn {key, value} ->
          setting_name = String.to_existing_atom(key)

          # Use set_organization_setting_with_user for permission checks on quota settings
          if schema_name == "organization" do
            Configurations.set_organization_setting_with_user(
              organization,
              user,
              setting_name,
              value
            )
          else
            Configurations.set_setting("Organization", organization.id, setting_name, value)
          end
        end)

      # Check if any errors occurred
      errors = Enum.filter(results, fn result -> match?({:error, _}, result) end)

      if Enum.empty?(errors) do
        # Get updated settings
        settings = Configurations.get_all_settings("Organization", organization.id)

        configuration_data = %{
          id: organization.id,
          schema_name: schema_name,
          settings: settings,
          updated_at: NaiveDateTime.utc_now()
        }

        render_api_response(conn, configuration_data, resource_type: "configuration")
      else
        # Extract error messages
        error_messages = Enum.map(errors, fn {:error, msg} -> msg end)

        render_error_response(
          conn,
          :unprocessable_entity,
          "validation_error",
          "Failed to update some settings: #{Enum.join(error_messages, ", ")}"
        )
      end
    else
      {:error, response} -> response
    end
  end

  def update_configuration(conn, _params) do
    with :ok <- ensure_scope(conn, "organizations:write") do
      render_error_response(
        conn,
        :bad_request,
        "invalid_request",
        "Request must include settings parameters"
      )
    else
      {:error, response} -> response
    end
  end

  # Private Functions

  defp filter_settings_by_permission(schema_name, settings, user) do
    # Only filter for organization schema (global schema has no quota settings)
    if schema_name == "organization" do
      schema_module = Authify.Configurations.Schemas.Organization

      # Get list of super_admin_only setting names
      super_admin_only_settings =
        schema_module.settings()
        |> Enum.filter(&Map.get(&1, :super_admin_only, false))
        |> Enum.map(& &1.name)

      # If not a super admin, remove quota settings from the map
      if Authify.Accounts.User.super_admin?(user) do
        settings
      else
        Map.drop(settings, super_admin_only_settings)
      end
    else
      settings
    end
  end
end
