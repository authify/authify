defmodule AuthifyWeb.Controllers.Shared.ResourceHelpers do
  @moduledoc """
  Shared utility functions for resource management used across different API protocols.
  """

  @doc """
  Parses pagination parameters from a map, returning {page, per_page}.

  Defaults are page=1 and per_page=25, with a maximum of 100 items per page.
  Pass a different `default_per_page` for endpoints that use a different default.
  """
  def parse_api_pagination(params, default_per_page \\ 25) do
    page = String.to_integer(params["page"] || "1")
    per_page = min(String.to_integer(params["per_page"] || "#{default_per_page}"), 100)

    {page, per_page}
  end

  @doc """
  Validates that a resource belongs to the given organization.
  Returns :ok if the resource's organization_id matches the organization's id,
  otherwise returns {:error, :not_found}.
  """
  def validate_resource_organization(resource, organization) do
    if resource.organization_id == organization.id do
      :ok
    else
      {:error, :not_found}
    end
  end
end
