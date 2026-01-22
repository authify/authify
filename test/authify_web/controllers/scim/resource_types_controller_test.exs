defmodule AuthifyWeb.SCIM.ResourceTypesControllerTest do
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

  describe "GET /scim/v2/ResourceTypes" do
    test "returns list of resource types", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/scim/v2/ResourceTypes")

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

      # Find User and Group resource types
      user_type = Enum.find(resources, &(&1["id"] == "User"))
      group_type = Enum.find(resources, &(&1["id"] == "Group"))

      # Verify User resource type
      assert user_type["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"]
      assert user_type["name"] == "User"
      assert user_type["endpoint"] == "/Users"
      assert user_type["description"] == "User Account"
      assert user_type["schema"] == "urn:ietf:params:scim:schemas:core:2.0:User"
      assert user_type["meta"]["resourceType"] == "ResourceType"

      assert user_type["meta"]["location"] ==
               "http://localhost:4002/#{organization.slug}/scim/v2/ResourceTypes/User"

      # Verify Group resource type
      assert group_type["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"]
      assert group_type["name"] == "Group"
      assert group_type["endpoint"] == "/Groups"
      assert group_type["description"] == "Group"
      assert group_type["schema"] == "urn:ietf:params:scim:schemas:core:2.0:Group"

      assert group_type["meta"]["location"] ==
               "http://localhost:4002/#{organization.slug}/scim/v2/ResourceTypes/Group"
    end
  end

  describe "GET /scim/v2/ResourceTypes/:id" do
    test "returns User resource type", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/scim/v2/ResourceTypes/User")

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"]
      assert response["id"] == "User"
      assert response["name"] == "User"
      assert response["endpoint"] == "/Users"
      assert response["schema"] == "urn:ietf:params:scim:schemas:core:2.0:User"
    end

    test "returns Group resource type", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/scim/v2/ResourceTypes/Group")

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["id"] == "Group"
      assert response["name"] == "Group"
      assert response["endpoint"] == "/Groups"
      assert response["schema"] == "urn:ietf:params:scim:schemas:core:2.0:Group"
    end

    test "returns 404 for unknown resource type", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/scim/v2/ResourceTypes/Unknown")

      assert conn.status == 404
      response = json_response(conn, 404)

      assert response["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
      assert response["status"] == "404"
      assert response["scimType"] == "noTarget"
      assert response["detail"] == "ResourceType 'Unknown' not found"
    end
  end
end
