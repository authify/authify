defmodule AuthifyWeb.ConfigurationController do
  use AuthifyWeb, :controller

  alias Authify.Configurations
  alias Authify.Organizations
  alias AuthifyWeb.Helpers.AuditHelper

  def show(conn, _params) do
    user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    # Determine schema based on organization
    {schema_name, all_settings} =
      if organization.slug == "authify-global" do
        {"global", Configurations.get_all_settings("Organization", organization.id)}
      else
        {"organization", Configurations.get_all_settings("Organization", organization.id)}
      end

    # Filter quota settings based on user permissions
    settings = filter_settings_by_permission(schema_name, all_settings, user)

    # For global org, derive authify_domain from CNAME (if set)
    authify_domain =
      if organization.slug == "authify-global" do
        get_authify_domain(organization)
      else
        nil
      end

    # Get tenant_base_domain for use in placeholders
    tenant_base_domain = Configurations.get_global_setting(:tenant_base_domain)

    # Add tenant_base_domain to settings for template access
    settings_with_base_domain = Map.put(settings, :tenant_base_domain, tenant_base_domain)

    # Get custom domains for tenant organizations (join by newline)
    custom_domains =
      if organization.slug != "authify-global" do
        organization
        |> Organizations.list_organization_cnames()
        |> Enum.map_join("\n", & &1.domain)
      else
        # For global org, custom_domains is managed via authify_domain abstraction
        ""
      end

    render(conn, :show,
      user: user,
      organization: organization,
      schema_name: schema_name,
      settings: settings_with_base_domain,
      authify_domain: authify_domain,
      custom_domains: custom_domains,
      is_super_admin: Authify.Accounts.User.super_admin?(user),
      page_title: "Configuration"
    )
  end

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

  defp get_authify_domain(organization) do
    email_link_domain = Configurations.get_global_setting(:email_link_domain)
    tenant_base_domain = Configurations.get_global_setting(:tenant_base_domain)
    default_domain = "#{organization.slug}.#{tenant_base_domain}"

    # If email_link_domain is set and different from default, it's a custom authify_domain
    if email_link_domain && email_link_domain != default_domain do
      email_link_domain
    else
      ""
    end
  end

  def update(conn, params) do
    user = conn.assigns.current_user
    organization = conn.assigns.current_organization
    schema_name = determine_schema_name(organization)

    _config =
      Configurations.get_or_create_configuration("Organization", organization.id, schema_name)

    old_settings = Configurations.get_all_settings("Organization", organization.id)
    complete_settings = normalize_boolean_settings(params, schema_name)

    # Process domains first, then settings
    case process_domain_updates(organization, params) do
      {:error, domain_type, reason} ->
        handle_domain_error(conn, organization, schema_name, domain_type, reason)

      :ok ->
        process_settings_updates(
          conn,
          organization,
          user,
          schema_name,
          old_settings,
          complete_settings
        )
    end
  end

  defp determine_schema_name(%{slug: "authify-global"}), do: "global"
  defp determine_schema_name(_organization), do: "organization"

  defp normalize_boolean_settings(params, schema_name) do
    settings_params = Map.get(params, "settings", %{})
    schema_module = get_schema_module(schema_name)
    boolean_settings = extract_boolean_setting_names(schema_module)

    Enum.reduce(boolean_settings, settings_params, fn setting_name, acc ->
      setting_key = to_string(setting_name)
      if Map.has_key?(acc, setting_key), do: acc, else: Map.put(acc, setting_key, "false")
    end)
  end

  defp get_schema_module("global"), do: Authify.Configurations.Schemas.Global
  defp get_schema_module("organization"), do: Authify.Configurations.Schemas.Organization

  defp extract_boolean_setting_names(schema_module) do
    schema_module.settings()
    |> Enum.filter(&(&1.value_type == :boolean))
    |> Enum.map(& &1.name)
  end

  defp process_domain_updates(organization, params) do
    authify_domain = Map.get(params, "authify_domain")
    custom_domains = Map.get(params, "custom_domains")

    case process_authify_domain(organization, authify_domain) do
      {:error, reason} ->
        {:error, :authify_domain, reason}

      _ ->
        case process_custom_domains(organization, custom_domains) do
          {:error, reason} -> {:error, :custom_domains, reason}
          _ -> :ok
        end
    end
  end

  defp process_authify_domain(%{slug: "authify-global"} = organization, authify_domain)
       when not is_nil(authify_domain) do
    handle_authify_domain_update(organization, authify_domain)
  end

  defp process_authify_domain(_organization, _authify_domain), do: :ok

  defp process_custom_domains(organization, custom_domains)
       when not is_nil(custom_domains) do
    if organization.slug == "authify-global" do
      :ok
    else
      handle_custom_domains_update(organization, custom_domains)
    end
  end

  defp process_custom_domains(_organization, _custom_domains), do: :ok

  defp process_settings_updates(
         conn,
         organization,
         user,
         schema_name,
         old_settings,
         complete_settings
       ) do
    results = apply_settings_updates(organization, user, schema_name, complete_settings)
    errors = Enum.filter(results, &match?({:error, _}, &1))

    if Enum.empty?(errors) do
      handle_update_success(conn, organization, schema_name, old_settings)
    else
      error_messages = Enum.map(errors, fn {:error, msg} -> msg end)
      handle_settings_error(conn, organization, schema_name, error_messages)
    end
  end

  defp apply_settings_updates(organization, user, schema_name, complete_settings) do
    Enum.map(complete_settings, fn {key, value} ->
      setting_name = String.to_existing_atom(key)
      update_single_setting(organization, user, schema_name, setting_name, value)
    end)
  end

  defp update_single_setting(organization, user, "organization", setting_name, value) do
    Configurations.set_organization_setting_with_user(organization, user, setting_name, value)
  end

  defp update_single_setting(organization, _user, _schema_name, setting_name, value) do
    Configurations.set_setting("Organization", organization.id, setting_name, value)
  end

  defp handle_update_success(conn, organization, schema_name, old_settings) do
    new_settings = Configurations.get_all_settings("Organization", organization.id)

    AuditHelper.log_configuration_update(
      conn,
      schema_name,
      old_settings,
      new_settings,
      resource_id: organization.id,
      resource_type: "configuration",
      extra_metadata: %{
        custom_domains:
          Organizations.list_organization_cnames(organization) |> Enum.map(& &1.domain)
      }
    )

    conn
    |> put_flash(:info, "Configuration updated successfully.")
    |> redirect(to: ~p"/#{organization.slug}/settings/configuration")
  end

  defp handle_domain_error(conn, organization, schema_name, :authify_domain, reason) do
    error_message = "Authify domain #{reason}"

    AuditHelper.log_configuration_update_failure(
      conn,
      schema_name,
      [error_message],
      resource_id: organization.id,
      resource_type: "configuration"
    )

    conn
    |> put_flash(:error, error_message)
    |> redirect(to: ~p"/#{organization.slug}/settings/configuration")
  end

  defp handle_domain_error(conn, organization, schema_name, :custom_domains, reason) do
    error_message = "Custom domains #{reason}"

    AuditHelper.log_configuration_update_failure(
      conn,
      schema_name,
      [error_message],
      resource_id: organization.id,
      resource_type: "configuration"
    )

    conn
    |> put_flash(:error, error_message)
    |> redirect(to: ~p"/#{organization.slug}/settings/configuration")
  end

  defp handle_settings_error(conn, organization, schema_name, error_messages) do
    AuditHelper.log_configuration_update_failure(
      conn,
      schema_name,
      error_messages,
      resource_id: organization.id,
      resource_type: "configuration"
    )

    conn
    |> put_flash(:error, "Error updating some settings. Please check your input.")
    |> redirect(to: ~p"/#{organization.slug}/settings/configuration")
  end

  defp handle_authify_domain_update(organization, "") do
    # Remove custom authify domain - delete CNAME and clear email_link_domain
    cnames = Organizations.list_organization_cnames(organization)

    for cname <- cnames do
      Organizations.delete_cname(cname)
    end

    # Clear the global email_link_domain setting
    Configurations.set_global_setting(:email_link_domain, "")

    :ok
  end

  defp handle_authify_domain_update(organization, authify_domain) do
    tenant_base_domain = Configurations.get_global_setting(:tenant_base_domain)
    default_domain = "#{organization.slug}.#{tenant_base_domain}"

    # If it's the same as default, just remove any CNAMEs
    if authify_domain == default_domain do
      handle_authify_domain_update(organization, "")
    else
      # Always clear ALL existing CNAMEs first to avoid accumulation
      current_cnames = Organizations.list_organization_cnames(organization)

      for cname <- current_cnames do
        Organizations.delete_cname(cname)
      end

      # Create single new CNAME for the authify_domain
      case Organizations.create_cname(%{
             organization_id: organization.id,
             domain: authify_domain
           }) do
        {:ok, _cname} ->
          Configurations.set_global_setting(:email_link_domain, authify_domain)

        {:error, changeset} ->
          errors = Ecto.Changeset.traverse_errors(changeset, fn {msg, _opts} -> msg end)
          reason = errors |> Map.get(:domain, ["is invalid"]) |> List.first()
          {:error, reason}
      end
    end
  end

  defp handle_custom_domains_update(organization, custom_domains_text) do
    # Parse newline-separated domains, trim whitespace, filter empty lines
    desired_domains =
      custom_domains_text
      |> String.split("\n")
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&(&1 == ""))
      |> Enum.uniq()

    # Get current CNAMEs
    current_cnames = Organizations.list_organization_cnames(organization)
    current_domains = Enum.map(current_cnames, & &1.domain)

    # Determine which domains to add and which to remove
    domains_to_add = desired_domains -- current_domains
    domains_to_remove = current_domains -- desired_domains

    # Delete removed domains
    for cname <- current_cnames, cname.domain in domains_to_remove do
      Organizations.delete_cname(cname)
    end

    # Add new domains
    results =
      Enum.map(domains_to_add, fn domain ->
        Organizations.create_cname(%{
          organization_id: organization.id,
          domain: domain
        })
      end)

    # Check for any errors
    errors = Enum.filter(results, fn result -> match?({:error, _}, result) end)

    if Enum.empty?(errors) do
      :ok
    else
      # Get first error and extract message
      {:error, changeset} = hd(errors)
      error_map = Ecto.Changeset.traverse_errors(changeset, fn {msg, _opts} -> msg end)
      reason = error_map |> Map.get(:domain, ["is invalid"]) |> List.first()
      {:error, reason}
    end
  end
end
