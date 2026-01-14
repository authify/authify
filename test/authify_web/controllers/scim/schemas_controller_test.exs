defmodule AuthifyWeb.SCIM.SchemasControllerTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  setup %{conn: conn} do
    organization = organization_fixture()
    admin_user = user_fixture(organization: organization, role: "admin")

    conn =
      conn
      |> assign(:current_organization, organization)
      |> assign(:current_user, admin_user)
      |> assign(:api_authenticated, true)
      |> assign(:current_scopes, ["scim:read"])

    {:ok, conn: conn, organization: organization}
  end

  describe "GET /scim/v2/Schemas" do
    test "returns list of schemas", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/scim/v2/Schemas")

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == ["application/scim+json; charset=utf-8"]

      response = json_response(conn, 200)

      # Verify ListResponse format
      assert response["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
      assert response["totalResults"] == 2
      assert response["itemsPerPage"] == 2
      assert response["startIndex"] == 1

      # Verify resources
      resources = response["Resources"]
      assert length(resources) == 2

      # Find User and Group schemas
      user_schema =
        Enum.find(resources, &(&1["id"] == "urn:ietf:params:scim:schemas:core:2.0:User"))

      group_schema =
        Enum.find(resources, &(&1["id"] == "urn:ietf:params:scim:schemas:core:2.0:Group"))

      # Verify User schema
      assert user_schema["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:Schema"]
      assert user_schema["name"] == "User"
      assert user_schema["description"] == "User Account"
      assert is_list(user_schema["attributes"])
      refute Enum.empty?(user_schema["attributes"])

      # Verify userName attribute exists
      username_attr = Enum.find(user_schema["attributes"], &(&1["name"] == "userName"))
      assert username_attr["type"] == "string"
      assert username_attr["required"] == true
      assert username_attr["uniqueness"] == "server"

      # Verify meta
      assert user_schema["meta"]["resourceType"] == "Schema"

      assert user_schema["meta"]["location"] ==
               "http://localhost:4002/#{organization.slug}/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User"

      # Verify Group schema
      assert group_schema["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:Schema"]
      assert group_schema["name"] == "Group"
      assert group_schema["description"] == "Group"
      assert is_list(group_schema["attributes"])

      # Verify displayName attribute exists
      displayname_attr = Enum.find(group_schema["attributes"], &(&1["name"] == "displayName"))
      assert displayname_attr["type"] == "string"
      assert displayname_attr["required"] == true
    end
  end

  describe "GET /scim/v2/Schemas/:id" do
    test "returns User schema", %{conn: conn, organization: organization} do
      conn =
        get(
          conn,
          "/#{organization.slug}/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User"
        )

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:Schema"]
      assert response["id"] == "urn:ietf:params:scim:schemas:core:2.0:User"
      assert response["name"] == "User"
      assert response["description"] == "User Account"

      # Verify attributes structure
      assert is_list(response["attributes"])

      # Verify userName attribute
      username_attr = Enum.find(response["attributes"], &(&1["name"] == "userName"))
      assert username_attr["type"] == "string"
      assert username_attr["multiValued"] == false
      assert username_attr["required"] == true
      assert username_attr["caseExact"] == false
      assert username_attr["mutability"] == "readWrite"
      assert username_attr["returned"] == "default"
      assert username_attr["uniqueness"] == "server"

      # Verify name complex attribute
      name_attr = Enum.find(response["attributes"], &(&1["name"] == "name"))
      assert name_attr["type"] == "complex"
      assert is_list(name_attr["subAttributes"])

      # Verify name subattributes
      given_name = Enum.find(name_attr["subAttributes"], &(&1["name"] == "givenName"))
      assert given_name["type"] == "string"

      family_name = Enum.find(name_attr["subAttributes"], &(&1["name"] == "familyName"))
      assert family_name["type"] == "string"

      # Verify emails complex attribute
      emails_attr = Enum.find(response["attributes"], &(&1["name"] == "emails"))
      assert emails_attr["type"] == "complex"
      assert emails_attr["multiValued"] == true
      assert is_list(emails_attr["subAttributes"])

      # Verify active boolean attribute
      active_attr = Enum.find(response["attributes"], &(&1["name"] == "active"))
      assert active_attr["type"] == "boolean"

      # Verify groups attribute (read-only)
      groups_attr = Enum.find(response["attributes"], &(&1["name"] == "groups"))
      assert groups_attr["mutability"] == "readOnly"

      # Verify externalId attribute
      external_id_attr = Enum.find(response["attributes"], &(&1["name"] == "externalId"))
      assert external_id_attr["type"] == "string"
      assert external_id_attr["caseExact"] == true
    end

    test "returns Group schema", %{conn: conn, organization: organization} do
      conn =
        get(
          conn,
          "/#{organization.slug}/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group"
        )

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["id"] == "urn:ietf:params:scim:schemas:core:2.0:Group"
      assert response["name"] == "Group"

      # Verify displayName attribute
      displayname_attr = Enum.find(response["attributes"], &(&1["name"] == "displayName"))
      assert displayname_attr["type"] == "string"
      assert displayname_attr["required"] == true

      # Verify members complex attribute
      members_attr = Enum.find(response["attributes"], &(&1["name"] == "members"))
      assert members_attr["type"] == "complex"
      assert members_attr["multiValued"] == true
      assert is_list(members_attr["subAttributes"])

      # Verify $ref subattribute
      ref_attr = Enum.find(members_attr["subAttributes"], &(&1["name"] == "$ref"))
      assert ref_attr["type"] == "reference"
      assert ref_attr["referenceTypes"] == ["User", "Group"]
    end

    test "returns 404 for unknown schema", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/scim/v2/Schemas/urn:unknown:schema")

      assert conn.status == 404
      response = json_response(conn, 404)

      assert response["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
      assert response["status"] == "404"
      assert response["scimType"] == "noTarget"
      assert String.contains?(response["detail"], "urn:unknown:schema")
    end
  end
end
