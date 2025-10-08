defmodule AuthifyWeb.ConfigurationController do
  use AuthifyWeb, :controller

  alias Authify.Configurations
  alias Authify.Organizations

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
        |> Enum.map(& &1.domain)
        |> Enum.join("\n")
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
    settings_params = Map.get(params, "settings", %{})
    authify_domain = Map.get(params, "authify_domain")
    custom_domains = Map.get(params, "custom_domains")

    # Determine schema based on organization
    schema_name =
      if organization.slug == "authify-global" do
        "global"
      else
        "organization"
      end

    # Ensure configuration exists
    _config =
      Configurations.get_or_create_configuration("Organization", organization.id, schema_name)

    # Get the schema module to know which settings are boolean
    schema_module =
      case schema_name do
        "global" -> Authify.Configurations.Schemas.Global
        "organization" -> Authify.Configurations.Schemas.Organization
      end

    # Get all boolean settings from the schema
    boolean_settings =
      schema_module.settings()
      |> Enum.filter(&(&1.value_type == :boolean))
      |> Enum.map(& &1.name)

    # Build complete settings map:
    # - Include all provided settings
    # - For boolean settings not in params, explicitly set to false
    complete_settings =
      Enum.reduce(boolean_settings, settings_params, fn setting_name, acc ->
        setting_key = to_string(setting_name)

        if Map.has_key?(acc, setting_key) do
          acc
        else
          # Boolean checkbox not checked, set to false
          Map.put(acc, setting_key, "false")
        end
      end)

    # IMPORTANT: Process domains BEFORE settings
    # This ensures email_link_domain validation sees the updated CNAMEs

    # Handle authify_domain for global organization
    authify_domain_result =
      if organization.slug == "authify-global" && authify_domain != nil do
        handle_authify_domain_update(organization, authify_domain)
      else
        :ok
      end

    # Handle custom_domains for tenant organizations
    # Only process if custom_domains was actually provided in the params
    custom_domains_result =
      if organization.slug != "authify-global" && custom_domains != nil do
        handle_custom_domains_update(organization, custom_domains)
      else
        :ok
      end

    # NOW update each setting (after domains are processed)
    results =
      Enum.map(complete_settings, fn {key, value} ->
        setting_name = String.to_existing_atom(key)

        # Use appropriate setter based on schema
        if schema_name == "organization" do
          # Use set_organization_setting_with_user for permission checks on quota settings
          Configurations.set_organization_setting_with_user(
            organization,
            user,
            setting_name,
            value
          )
        else
          # Use generic set_setting for global settings
          Configurations.set_setting("Organization", organization.id, setting_name, value)
        end
      end)

    # Check if any errors occurred
    errors = Enum.filter(results, fn result -> match?({:error, _}, result) end)

    cond do
      match?({:error, _}, authify_domain_result) ->
        {:error, reason} = authify_domain_result

        conn
        |> put_flash(:error, "Authify domain #{reason}")
        |> redirect(to: ~p"/#{organization.slug}/settings/configuration")

      match?({:error, _}, custom_domains_result) ->
        {:error, reason} = custom_domains_result

        conn
        |> put_flash(:error, "Custom domains #{reason}")
        |> redirect(to: ~p"/#{organization.slug}/settings/configuration")

      Enum.empty?(errors) ->
        conn
        |> put_flash(:info, "Configuration updated successfully.")
        |> redirect(to: ~p"/#{organization.slug}/settings/configuration")

      true ->
        conn
        |> put_flash(:error, "Error updating some settings. Please check your input.")
        |> redirect(to: ~p"/#{organization.slug}/settings/configuration")
    end
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
