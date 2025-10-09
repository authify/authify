defmodule Authify.Organizations do
  @moduledoc """
  Context for organization domain management.

  Handles organization CNAMEs and domain-related operations.
  """

  import Ecto.Query
  alias Authify.Accounts.Organization
  alias Authify.Configurations
  alias Authify.Organizations.OrganizationCname
  alias Authify.Repo

  @doc """
  Gets the list of allowed domains for an organization.

  Returns a list containing:
  - The auto-generated subdomain ({org_slug}.{tenant_base_domain})
  - All custom CNAMEs for the organization
  """
  def get_allowed_domains(%Organization{} = org) do
    cnames = list_organization_cnames(org)
    base_domain = Configurations.get_global_setting(:tenant_base_domain)
    subdomain = "#{org.slug}.#{base_domain}"

    [subdomain | Enum.map(cnames, & &1.domain)]
  end

  @doc """
  Gets the default domain for an organization.

  Returns the auto-generated subdomain based on tenant_base_domain.
  The tenant_base_domain is a required global setting, so this should always return a value.
  """
  def get_default_domain(%Organization{} = org) do
    base_domain = Configurations.get_global_setting(:tenant_base_domain)
    "#{org.slug}.#{base_domain}"
  end

  @doc """
  Lists all CNAMEs for an organization.
  """
  def list_organization_cnames(%Organization{id: org_id}) do
    OrganizationCname
    |> where([c], c.organization_id == ^org_id)
    |> order_by([c], asc: c.domain)
    |> Repo.all()
  end

  @doc """
  Gets a single CNAME.
  """
  def get_cname!(id), do: Repo.get!(OrganizationCname, id)

  @doc """
  Creates a CNAME for an organization.
  """
  def create_cname(attrs \\ %{}) do
    %OrganizationCname{}
    |> OrganizationCname.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a CNAME.
  """
  def update_cname(%OrganizationCname{} = cname, attrs) do
    cname
    |> OrganizationCname.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a CNAME.

  Also resets the email_link_domain configuration if it was using this CNAME.
  """
  def delete_cname(%OrganizationCname{} = cname) do
    cname = Repo.preload(cname, :organization)

    with {:ok, deleted_cname} <- Repo.delete(cname) do
      # Check if email_link_domain was using this domain
      maybe_reset_email_link_domain(cname.organization, cname.domain)
      {:ok, deleted_cname}
    end
  end

  defp maybe_reset_email_link_domain(org, deleted_domain) do
    current_email_domain = Configurations.get_organization_setting(org, :email_link_domain)

    if current_email_domain == deleted_domain do
      # Reset to default domain
      default = get_default_domain(org)
      Configurations.set_organization_setting(org, :email_link_domain, default)
    end
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking CNAME changes.
  """
  def change_cname(%OrganizationCname{} = cname, attrs \\ %{}) do
    OrganizationCname.changeset(cname, attrs)
  end

  @doc """
  Gets the effective email link domain for an organization.

  Returns the configured email_link_domain if set, otherwise falls back
  to the default domain (subdomain or first CNAME).
  """
  def get_email_link_domain(%Organization{} = org) do
    configured = Configurations.get_organization_setting(org, :email_link_domain)

    if configured && configured != "" do
      configured
    else
      get_default_domain(org)
    end
  end
end
