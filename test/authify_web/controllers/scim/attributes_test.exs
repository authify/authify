defmodule AuthifyWeb.SCIM.AttributesTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  setup %{conn: conn} do
    organization = organization_fixture()
    user = user_fixture(organization: organization, email: "test@example.com")

    conn =
      conn
      |> assign(:current_organization, organization)
      |> assign(:current_user, user)
      |> assign(:api_authenticated, true)
      |> assign(:current_scopes, ["scim:read", "scim:write"])

    {:ok, conn: conn, organization: organization, user: user}
  end

  describe "attributes parameter on Users" do
    test "returns only requested attributes", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      conn =
        get(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}?attributes=userName,emails")

      assert conn.status == 200
      response = json_response(conn, 200)

      # Should include requested attributes
      assert response["userName"]
      assert response["emails"]

      # Should always include required attributes
      assert response["id"]
      assert response["schemas"]
      assert response["meta"]

      # Should NOT include unrequested attributes
      refute Map.has_key?(response, "name")
      refute Map.has_key?(response, "active")
      refute Map.has_key?(response, "groups")
    end

    test "supports nested attribute requests", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      conn =
        get(
          conn,
          "/#{organization.slug}/scim/v2/Users/#{user.id}?attributes=userName,name.givenName"
        )

      assert conn.status == 200
      response = json_response(conn, 200)

      # Should include parent attribute with only requested sub-attributes
      assert response["userName"]
      assert response["name"]["givenName"]
      refute Map.has_key?(response["name"], "familyName")
    end

    test "works with list endpoint", %{conn: conn, organization: organization} do
      user_fixture(organization: organization, email: "user1@example.com")
      user_fixture(organization: organization, email: "user2@example.com")

      conn = get(conn, "/#{organization.slug}/scim/v2/Users?attributes=userName,active")

      assert conn.status == 200
      response = json_response(conn, 200)

      # Check first user in results
      first_user = hd(response["Resources"])
      assert first_user["userName"]
      assert Map.has_key?(first_user, "active")
      refute Map.has_key?(first_user, "name")
      refute Map.has_key?(first_user, "emails")
    end

    test "ignores empty attributes parameter", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      conn = get(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}?attributes=")

      assert conn.status == 200
      response = json_response(conn, 200)

      # Should return full resource
      assert response["userName"]
      assert response["name"]
      assert response["emails"]
      assert response["active"]
    end
  end

  describe "excludedAttributes parameter on Users" do
    test "excludes requested attributes", %{conn: conn, organization: organization, user: user} do
      conn =
        get(
          conn,
          "/#{organization.slug}/scim/v2/Users/#{user.id}?excludedAttributes=groups,emails"
        )

      assert conn.status == 200
      response = json_response(conn, 200)

      # Should include non-excluded attributes
      assert response["userName"]
      assert response["name"]
      assert response["active"]

      # Should NOT include excluded attributes
      refute Map.has_key?(response, "groups")
      refute Map.has_key?(response, "emails")

      # Should always include required attributes even if excluded
      assert response["id"]
      assert response["schemas"]
      assert response["meta"]
    end

    test "cannot exclude required attributes", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      conn =
        get(
          conn,
          "/#{organization.slug}/scim/v2/Users/#{user.id}?excludedAttributes=id,schemas,meta"
        )

      assert conn.status == 200
      response = json_response(conn, 200)

      # Required attributes should still be present
      assert response["id"]
      assert response["schemas"]
      assert response["meta"]
    end

    test "works with list endpoint", %{conn: conn, organization: organization} do
      user_fixture(organization: organization, email: "user1@example.com")
      user_fixture(organization: organization, email: "user2@example.com")

      conn = get(conn, "/#{organization.slug}/scim/v2/Users?excludedAttributes=groups,name")

      assert conn.status == 200
      response = json_response(conn, 200)

      first_user = hd(response["Resources"])
      assert first_user["userName"]
      assert first_user["emails"]
      refute Map.has_key?(first_user, "groups")
      refute Map.has_key?(first_user, "name")
    end
  end

  describe "attributes parameter on Groups" do
    test "returns only requested attributes", %{conn: conn, organization: organization} do
      group = group_fixture(organization: organization, name: "Test Group")

      conn = get(conn, "/#{organization.slug}/scim/v2/Groups/#{group.id}?attributes=displayName")

      assert conn.status == 200
      response = json_response(conn, 200)

      # Should include requested attributes
      assert response["displayName"]

      # Should always include required attributes
      assert response["id"]
      assert response["schemas"]
      assert response["meta"]

      # Should NOT include unrequested attributes
      refute Map.has_key?(response, "members")
    end

    test "works with list endpoint", %{conn: conn, organization: organization} do
      group_fixture(organization: organization, name: "Group 1")
      group_fixture(organization: organization, name: "Group 2")

      conn = get(conn, "/#{organization.slug}/scim/v2/Groups?attributes=displayName,id")

      assert conn.status == 200
      response = json_response(conn, 200)

      first_group = hd(response["Resources"])
      assert first_group["displayName"]
      assert first_group["id"]
      refute Map.has_key?(first_group, "members")
    end
  end

  describe "excludedAttributes parameter on Groups" do
    test "excludes requested attributes", %{conn: conn, organization: organization} do
      group = group_fixture(organization: organization, name: "Test Group")

      conn =
        get(conn, "/#{organization.slug}/scim/v2/Groups/#{group.id}?excludedAttributes=members")

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["displayName"]
      refute Map.has_key?(response, "members")
    end
  end

  describe "attributes parameter on /Me endpoint" do
    test "returns only requested attributes", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/scim/v2/Me?attributes=userName,emails")

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["userName"]
      assert response["emails"]
      assert response["id"]
      refute Map.has_key?(response, "name")
      refute Map.has_key?(response, "groups")
    end

    test "excludedAttributes works", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/scim/v2/Me?excludedAttributes=groups")

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["userName"]
      refute Map.has_key?(response, "groups")
    end
  end

  describe "parameter precedence" do
    test "attributes takes precedence over excludedAttributes", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      # If both are provided, attributes should win
      conn =
        get(
          conn,
          "/#{organization.slug}/scim/v2/Users/#{user.id}?attributes=userName&excludedAttributes=userName"
        )

      assert conn.status == 200
      response = json_response(conn, 200)

      # attributes parameter should win
      assert response["userName"]
    end
  end

  describe "complex nested attributes" do
    test "filters complex multi-valued attributes", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      conn = get(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}?attributes=emails.value")

      assert conn.status == 200
      response = json_response(conn, 200)

      # Should include emails with only value field
      assert is_list(response["emails"])

      unless Enum.empty?(response["emails"]) do
        first_email = hd(response["emails"])
        assert first_email["value"]
        # Should not include other email fields like type, primary
        refute Map.has_key?(first_email, "type")
        refute Map.has_key?(first_email, "primary")
      end
    end
  end
end
