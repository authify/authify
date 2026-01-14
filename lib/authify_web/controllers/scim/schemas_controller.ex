defmodule AuthifyWeb.SCIM.SchemasController do
  @moduledoc """
  SCIM 2.0 Schemas endpoint per RFC 7644 Section 4.

  Returns schema definitions for User and Group resources.
  """

  use AuthifyWeb.SCIM.BaseController

  @user_schema %{
    id: "urn:ietf:params:scim:schemas:core:2.0:User",
    name: "User",
    description: "User Account",
    attributes: [
      %{
        name: "userName",
        type: "string",
        multiValued: false,
        description:
          "Unique identifier for the User, typically used by the user to directly authenticate",
        required: true,
        caseExact: false,
        mutability: "readWrite",
        returned: "default",
        uniqueness: "server"
      },
      %{
        name: "name",
        type: "complex",
        multiValued: false,
        description: "The components of the user's real name",
        required: false,
        subAttributes: [
          %{
            name: "formatted",
            type: "string",
            multiValued: false,
            description: "The full name, including all middle names, titles, and suffixes",
            required: false,
            caseExact: false,
            mutability: "readWrite",
            returned: "default",
            uniqueness: "none"
          },
          %{
            name: "familyName",
            type: "string",
            multiValued: false,
            description: "The family name of the User, or last name",
            required: false,
            caseExact: false,
            mutability: "readWrite",
            returned: "default",
            uniqueness: "none"
          },
          %{
            name: "givenName",
            type: "string",
            multiValued: false,
            description: "The given name of the User, or first name",
            required: false,
            caseExact: false,
            mutability: "readWrite",
            returned: "default",
            uniqueness: "none"
          }
        ],
        mutability: "readWrite",
        returned: "default",
        uniqueness: "none"
      },
      %{
        name: "emails",
        type: "complex",
        multiValued: true,
        description: "Email addresses for the user",
        required: false,
        subAttributes: [
          %{
            name: "value",
            type: "string",
            multiValued: false,
            description: "Email address",
            required: false,
            caseExact: false,
            mutability: "readWrite",
            returned: "default",
            uniqueness: "none"
          },
          %{
            name: "type",
            type: "string",
            multiValued: false,
            description: "Type of email address (e.g., work, home)",
            required: false,
            caseExact: false,
            mutability: "readWrite",
            returned: "default",
            uniqueness: "none"
          },
          %{
            name: "primary",
            type: "boolean",
            multiValued: false,
            description: "Whether this is the primary email",
            required: false,
            mutability: "readWrite",
            returned: "default",
            uniqueness: "none"
          }
        ],
        mutability: "readWrite",
        returned: "default",
        uniqueness: "none"
      },
      %{
        name: "active",
        type: "boolean",
        multiValued: false,
        description: "A Boolean value indicating the User's administrative status",
        required: false,
        mutability: "readWrite",
        returned: "default",
        uniqueness: "none"
      },
      %{
        name: "groups",
        type: "complex",
        multiValued: true,
        description: "A list of groups to which the user belongs",
        required: false,
        subAttributes: [
          %{
            name: "value",
            type: "string",
            multiValued: false,
            description: "The identifier of the group",
            required: false,
            caseExact: false,
            mutability: "readOnly",
            returned: "default",
            uniqueness: "none"
          },
          %{
            name: "$ref",
            type: "reference",
            referenceTypes: ["Group"],
            multiValued: false,
            description: "The URI of the group resource",
            required: false,
            caseExact: false,
            mutability: "readOnly",
            returned: "default",
            uniqueness: "none"
          },
          %{
            name: "display",
            type: "string",
            multiValued: false,
            description: "A human-readable name for the group",
            required: false,
            caseExact: false,
            mutability: "readOnly",
            returned: "default",
            uniqueness: "none"
          }
        ],
        mutability: "readOnly",
        returned: "default",
        uniqueness: "none"
      },
      %{
        name: "externalId",
        type: "string",
        multiValued: false,
        description: "Identifier from the provisioning client",
        required: false,
        caseExact: true,
        mutability: "readWrite",
        returned: "default",
        uniqueness: "none"
      }
    ]
  }

  @group_schema %{
    id: "urn:ietf:params:scim:schemas:core:2.0:Group",
    name: "Group",
    description: "Group",
    attributes: [
      %{
        name: "displayName",
        type: "string",
        multiValued: false,
        description: "A human-readable name for the Group",
        required: true,
        caseExact: false,
        mutability: "readWrite",
        returned: "default",
        uniqueness: "none"
      },
      %{
        name: "members",
        type: "complex",
        multiValued: true,
        description: "A list of members of the Group",
        required: false,
        subAttributes: [
          %{
            name: "value",
            type: "string",
            multiValued: false,
            description: "Identifier of the member",
            required: false,
            caseExact: false,
            mutability: "readWrite",
            returned: "default",
            uniqueness: "none"
          },
          %{
            name: "$ref",
            type: "reference",
            referenceTypes: ["User", "Group"],
            multiValued: false,
            description: "The URI of the member resource",
            required: false,
            caseExact: false,
            mutability: "readWrite",
            returned: "default",
            uniqueness: "none"
          },
          %{
            name: "display",
            type: "string",
            multiValued: false,
            description: "A human-readable name for the member",
            required: false,
            caseExact: false,
            mutability: "readWrite",
            returned: "default",
            uniqueness: "none"
          }
        ],
        mutability: "readWrite",
        returned: "default",
        uniqueness: "none"
      },
      %{
        name: "externalId",
        type: "string",
        multiValued: false,
        description: "Identifier from the provisioning client",
        required: false,
        caseExact: true,
        mutability: "readWrite",
        returned: "default",
        uniqueness: "none"
      }
    ]
  }

  @doc """
  GET /scim/v2/Schemas

  Returns all available schemas.
  """
  def index(conn, _params) do
    base_url = build_base_url(conn)

    schemas = [
      add_schema_meta(@user_schema, base_url),
      add_schema_meta(@group_schema, base_url)
    ]

    render_scim_list(conn, schemas, 2, 1, 100, :schema)
  end

  @doc """
  GET /scim/v2/Schemas/:id

  Returns a specific schema (User or Group).
  """
  def show(conn, %{"id" => id}) do
    base_url = build_base_url(conn)

    schema =
      case id do
        "urn:ietf:params:scim:schemas:core:2.0:User" -> add_schema_meta(@user_schema, base_url)
        "urn:ietf:params:scim:schemas:core:2.0:Group" -> add_schema_meta(@group_schema, base_url)
        _ -> nil
      end

    if schema do
      render_scim_resource(conn, schema)
    else
      render_scim_error(conn, 404, :no_target, "Schema '#{id}' not found")
    end
  end

  defp build_base_url(conn) do
    org_slug = conn.assigns[:current_organization].slug
    "#{AuthifyWeb.Endpoint.url()}/#{org_slug}/scim/v2"
  end

  defp add_schema_meta(schema, base_url) do
    schema
    |> Map.put(:schemas, ["urn:ietf:params:scim:schemas:core:2.0:Schema"])
    |> Map.put(:meta, %{
      resourceType: "Schema",
      location: "#{base_url}/Schemas/#{schema.id}"
    })
  end
end
