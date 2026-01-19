defmodule AuthifyWeb.SCIM.ResourceTypesController do
  @moduledoc """
  SCIM 2.0 ResourceTypes endpoint per RFC 7644 Section 4.

  Describes the types of resources available (User, Group).
  """

  use AuthifyWeb.SCIM.BaseController

  alias AuthifyWeb.SCIM.Helpers

  @user_resource_type %{
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
    id: "User",
    name: "User",
    endpoint: "/Users",
    description: "User Account",
    schema: "urn:ietf:params:scim:schemas:core:2.0:User",
    schemaExtensions: []
  }

  @group_resource_type %{
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
    id: "Group",
    name: "Group",
    endpoint: "/Groups",
    description: "Group",
    schema: "urn:ietf:params:scim:schemas:core:2.0:Group",
    schemaExtensions: []
  }

  @doc """
  GET /scim/v2/ResourceTypes

  Returns all available resource types.
  """
  def index(conn, _params) do
    base_url = Helpers.build_base_url(conn)

    resources = [
      add_meta(@user_resource_type, "User", base_url),
      add_meta(@group_resource_type, "Group", base_url)
    ]

    render_scim_list(conn, resources, 2, 1, 100, :resource_type)
  end

  @doc """
  GET /scim/v2/ResourceTypes/:id

  Returns a specific resource type (User or Group).
  """
  def show(conn, %{"id" => id}) do
    base_url = Helpers.build_base_url(conn)

    resource =
      case id do
        "User" -> add_meta(@user_resource_type, "User", base_url)
        "Group" -> add_meta(@group_resource_type, "Group", base_url)
        _ -> nil
      end

    if resource do
      render_scim_resource(conn, resource)
    else
      render_scim_error(conn, 404, :no_target, "ResourceType '#{id}' not found")
    end
  end

  defp add_meta(resource, id, base_url) do
    Map.put(resource, :meta, %{
      resourceType: "ResourceType",
      location: "#{base_url}/ResourceTypes/#{id}"
    })
  end
end
