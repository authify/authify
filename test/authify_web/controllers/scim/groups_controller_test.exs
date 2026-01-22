defmodule AuthifyWeb.SCIM.GroupsControllerTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  alias Authify.Accounts

  setup %{conn: conn} do
    organization = organization_fixture()
    admin_user = user_fixture(organization: organization, role: "admin")

    conn =
      conn
      |> assign(:current_organization, organization)
      |> assign(:current_user, admin_user)
      |> assign(:api_authenticated, true)
      |> assign(:current_scopes, ["scim:read", "scim:write"])

    {:ok, conn: conn, organization: organization, admin_user: admin_user}
  end

  describe "GET /scim/v2/Groups" do
    test "returns list of groups with pagination", %{conn: conn, organization: organization} do
      # Create test groups
      {:ok, group1} =
        Accounts.create_group(%{name: "Engineering", organization_id: organization.id})

      {:ok, group2} = Accounts.create_group(%{name: "Sales", organization_id: organization.id})

      conn = get(conn, "/#{organization.slug}/scim/v2/Groups")

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == ["application/scim+json; charset=utf-8"]

      response = json_response(conn, 200)

      # Verify ListResponse format
      assert response["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
      assert response["totalResults"] >= 2
      assert response["startIndex"] == 1
      assert is_list(response["Resources"])

      # Verify group resources contain expected fields
      group_ids = Enum.map(response["Resources"], & &1["id"])
      assert to_string(group1.id) in group_ids
      assert to_string(group2.id) in group_ids
    end

    test "supports pagination with startIndex and count", %{
      conn: conn,
      organization: organization
    } do
      # Create 5 groups
      Enum.each(1..5, fn i ->
        Accounts.create_group(%{name: "Group #{i}", organization_id: organization.id})
      end)

      # Get first page
      conn = get(conn, "/#{organization.slug}/scim/v2/Groups?startIndex=1&count=2")
      response = json_response(conn, 200)

      assert response["startIndex"] == 1
      assert response["itemsPerPage"] == 2
      assert length(response["Resources"]) == 2

      # Get second page
      conn = build_conn()
      conn = assign(conn, :current_organization, organization)
      conn = assign(conn, :api_authenticated, true)
      conn = assign(conn, :current_scopes, ["scim:read"])

      conn = get(conn, "/#{organization.slug}/scim/v2/Groups?startIndex=3&count=2")
      response = json_response(conn, 200)

      assert response["startIndex"] == 3
      assert response["itemsPerPage"] == 2
    end

    test "respects max count of 100", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/scim/v2/Groups?count=200")
      response = json_response(conn, 200)

      # itemsPerPage should be capped at 100 or the actual number of groups, whichever is less
      assert response["itemsPerPage"] <= 100
    end

    test "filters groups by displayName", %{conn: conn, organization: organization} do
      {:ok, group} =
        Accounts.create_group(%{name: "Engineering", organization_id: organization.id})

      {:ok, _other} = Accounts.create_group(%{name: "Sales", organization_id: organization.id})

      conn =
        get(conn, "/#{organization.slug}/scim/v2/Groups?filter=displayName eq \"Engineering\"")

      response = json_response(conn, 200)

      assert response["totalResults"] == 1
      assert length(response["Resources"]) == 1
      assert hd(response["Resources"])["id"] == to_string(group.id)
      assert hd(response["Resources"])["displayName"] == "Engineering"
    end

    test "filters groups by externalId", %{conn: conn, organization: organization} do
      {:ok, group} =
        Accounts.create_group(%{
          name: "Engineering",
          external_id: "ext123",
          organization_id: organization.id
        })

      {:ok, _other} =
        Accounts.create_group(%{
          name: "Sales",
          external_id: "ext456",
          organization_id: organization.id
        })

      conn = get(conn, "/#{organization.slug}/scim/v2/Groups?filter=externalId eq \"ext123\"")
      response = json_response(conn, 200)

      assert response["totalResults"] == 1
      assert hd(response["Resources"])["id"] == to_string(group.id)
      assert hd(response["Resources"])["externalId"] == "ext123"
    end

    test "returns error for invalid filter", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/scim/v2/Groups?filter=invalidField eq \"value\"")

      assert conn.status == 400
      response = json_response(conn, 400)

      assert response["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
      assert response["scimType"] == "invalidFilter"
    end

    test "requires scim:groups:read scope", %{conn: conn, organization: organization} do
      conn =
        conn
        |> assign(:current_scopes, ["other:scope"])

      conn = get(conn, "/#{organization.slug}/scim/v2/Groups")

      assert conn.status == 403
      response = json_response(conn, 403)
      assert response["scimType"] == "sensitive"
    end

    test "allows scim:read scope", %{conn: conn, organization: organization} do
      conn =
        conn
        |> assign(:current_scopes, ["scim:read"])

      conn = get(conn, "/#{organization.slug}/scim/v2/Groups")

      assert conn.status == 200
    end

    test "sorts groups by displayName ascending", %{conn: conn, organization: organization} do
      {:ok, _} = Accounts.create_group(%{name: "Zebra", organization_id: organization.id})
      {:ok, _} = Accounts.create_group(%{name: "Alpha", organization_id: organization.id})
      {:ok, _} = Accounts.create_group(%{name: "Beta", organization_id: organization.id})

      conn =
        get(conn, "/#{organization.slug}/scim/v2/Groups?sortBy=displayName&sortOrder=ascending")

      response = json_response(conn, 200)

      names = Enum.map(response["Resources"], & &1["displayName"])
      assert names == Enum.sort(names)
    end

    test "sorts groups by displayName descending", %{conn: conn, organization: organization} do
      {:ok, _} = Accounts.create_group(%{name: "Zebra", organization_id: organization.id})
      {:ok, _} = Accounts.create_group(%{name: "Alpha", organization_id: organization.id})
      {:ok, _} = Accounts.create_group(%{name: "Beta", organization_id: organization.id})

      conn =
        get(conn, "/#{organization.slug}/scim/v2/Groups?sortBy=displayName&sortOrder=descending")

      response = json_response(conn, 200)

      names = Enum.map(response["Resources"], & &1["displayName"])
      assert names == Enum.sort(names, :desc)
    end
  end

  describe "GET /scim/v2/Groups/:id" do
    test "returns a single group", %{conn: conn, organization: organization} do
      {:ok, group} =
        Accounts.create_group(%{name: "Engineering", organization_id: organization.id})

      conn = get(conn, "/#{organization.slug}/scim/v2/Groups/#{group.id}")

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:Group"]
      assert response["id"] == to_string(group.id)
      assert response["displayName"] == "Engineering"
      assert is_list(response["members"])
    end

    test "returns group with members", %{conn: conn, organization: organization} do
      {:ok, group} =
        Accounts.create_group(%{name: "Engineering", organization_id: organization.id})

      user1 = user_fixture(organization: organization, email: "user1@example.com")
      user2 = user_fixture(organization: organization, email: "user2@example.com")

      {:ok, _} = Accounts.add_user_to_group(user1, group)
      {:ok, _} = Accounts.add_user_to_group(user2, group)

      conn = get(conn, "/#{organization.slug}/scim/v2/Groups/#{group.id}")

      assert conn.status == 200
      response = json_response(conn, 200)

      assert length(response["members"]) == 2
      member_ids = Enum.map(response["members"], & &1["value"])
      assert to_string(user1.id) in member_ids
      assert to_string(user2.id) in member_ids
    end

    test "returns 404 for non-existent group", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/scim/v2/Groups/99999")

      assert conn.status == 404
      response = json_response(conn, 404)

      assert response["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
      assert response["scimType"] == "noTarget"
    end

    test "returns 404 for group from different organization", %{
      conn: conn,
      organization: organization
    } do
      other_org = organization_fixture()
      {:ok, group} = Accounts.create_group(%{name: "Other Group", organization_id: other_org.id})

      conn = get(conn, "/#{organization.slug}/scim/v2/Groups/#{group.id}")

      assert conn.status == 404
    end

    test "requires scim:groups:read scope", %{conn: conn, organization: organization} do
      {:ok, group} =
        Accounts.create_group(%{name: "Engineering", organization_id: organization.id})

      conn =
        conn
        |> assign(:current_scopes, ["other:scope"])

      conn = get(conn, "/#{organization.slug}/scim/v2/Groups/#{group.id}")

      assert conn.status == 403
    end
  end

  describe "POST /scim/v2/Groups" do
    test "creates a new group", %{conn: conn, organization: organization} do
      group_attrs = %{
        "displayName" => "Engineering",
        "externalId" => "ext-eng-123"
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Groups", group_attrs)

      assert conn.status == 201
      response = json_response(conn, 201)

      assert response["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:Group"]
      assert response["displayName"] == "Engineering"
      assert response["externalId"] == "ext-eng-123"
      assert response["id"]

      # Verify Location header
      location = get_resp_header(conn, "location") |> hd()
      assert location =~ "/scim/v2/Groups/#{response["id"]}"
    end

    test "creates group without externalId", %{conn: conn, organization: organization} do
      group_attrs = %{
        "displayName" => "Sales"
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Groups", group_attrs)

      assert conn.status == 201
      response = json_response(conn, 201)

      assert response["displayName"] == "Sales"
      refute response["externalId"]
    end

    test "returns error for missing required fields", %{conn: conn, organization: organization} do
      conn = post(conn, "/#{organization.slug}/scim/v2/Groups", %{})

      assert conn.status == 400
      response = json_response(conn, 400)

      assert response["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
      assert response["scimType"] == "invalidValue"
    end

    test "returns error for duplicate displayName", %{conn: conn, organization: organization} do
      {:ok, _} = Accounts.create_group(%{name: "Engineering", organization_id: organization.id})

      group_attrs = %{
        "displayName" => "Engineering"
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Groups", group_attrs)

      assert conn.status == 409
      response = json_response(conn, 409)

      assert response["scimType"] == "uniqueness"
      assert response["detail"] =~ "Engineering"
    end

    test "returns error for duplicate externalId", %{conn: conn, organization: organization} do
      {:ok, _} =
        Accounts.create_group(%{
          name: "Engineering",
          external_id: "ext123",
          organization_id: organization.id
        })

      group_attrs = %{
        "displayName" => "Sales",
        "externalId" => "ext123"
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Groups", group_attrs)

      assert conn.status == 409
      response = json_response(conn, 409)

      assert response["scimType"] == "uniqueness"
      assert response["detail"] =~ "ext123"
    end

    test "requires scim:groups:write scope", %{conn: conn, organization: organization} do
      conn =
        conn
        |> assign(:current_scopes, ["scim:read"])

      group_attrs = %{
        "displayName" => "Engineering"
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Groups", group_attrs)

      assert conn.status == 403
    end
  end

  describe "PUT /scim/v2/Groups/:id" do
    test "updates a group", %{conn: conn, organization: organization} do
      {:ok, group} =
        Accounts.create_group(%{
          name: "Engineering",
          external_id: "ext123",
          organization_id: organization.id
        })

      update_attrs = %{
        "displayName" => "Engineering Team",
        "externalId" => "ext123"
      }

      conn = put(conn, "/#{organization.slug}/scim/v2/Groups/#{group.id}", update_attrs)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["displayName"] == "Engineering Team"
      assert response["externalId"] == "ext123"
    end

    test "prevents modifying immutable externalId", %{conn: conn, organization: organization} do
      {:ok, group} =
        Accounts.create_group(%{
          name: "Engineering",
          external_id: "ext123",
          organization_id: organization.id
        })

      update_attrs = %{
        "displayName" => "Engineering Team",
        "externalId" => "ext456"
      }

      conn = put(conn, "/#{organization.slug}/scim/v2/Groups/#{group.id}", update_attrs)

      assert conn.status == 400
      response = json_response(conn, 400)

      assert response["scimType"] == "mutability"
      assert response["detail"] =~ "immutable"
    end

    test "returns 404 for non-existent group", %{conn: conn, organization: organization} do
      update_attrs = %{
        "displayName" => "New Name"
      }

      conn = put(conn, "/#{organization.slug}/scim/v2/Groups/99999", update_attrs)

      assert conn.status == 404
    end

    test "requires scim:groups:write scope", %{conn: conn, organization: organization} do
      {:ok, group} =
        Accounts.create_group(%{name: "Engineering", organization_id: organization.id})

      conn =
        conn
        |> assign(:current_scopes, ["scim:read"])

      update_attrs = %{
        "displayName" => "New Name"
      }

      conn = put(conn, "/#{organization.slug}/scim/v2/Groups/#{group.id}", update_attrs)

      assert conn.status == 403
    end
  end

  describe "PATCH /scim/v2/Groups/:id" do
    test "replaces displayName with path", %{conn: conn, organization: organization} do
      {:ok, group} =
        Accounts.create_group(%{name: "Engineering", organization_id: organization.id})

      patch_ops = %{
        "Operations" => [
          %{
            "op" => "replace",
            "path" => "displayName",
            "value" => "Engineering Team"
          }
        ]
      }

      conn = patch(conn, "/#{organization.slug}/scim/v2/Groups/#{group.id}", patch_ops)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["displayName"] == "Engineering Team"
    end

    test "replaces entire resource without path", %{conn: conn, organization: organization} do
      {:ok, group} =
        Accounts.create_group(%{name: "Engineering", organization_id: organization.id})

      patch_ops = %{
        "Operations" => [
          %{
            "op" => "replace",
            "value" => %{
              "displayName" => "Engineering Team"
            }
          }
        ]
      }

      conn = patch(conn, "/#{organization.slug}/scim/v2/Groups/#{group.id}", patch_ops)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["displayName"] == "Engineering Team"
    end

    test "adds members to group", %{conn: conn, organization: organization} do
      {:ok, group} =
        Accounts.create_group(%{name: "Engineering", organization_id: organization.id})

      user1 = user_fixture(organization: organization, email: "user1@example.com")
      user2 = user_fixture(organization: organization, email: "user2@example.com")

      patch_ops = %{
        "Operations" => [
          %{
            "op" => "add",
            "path" => "members",
            "value" => [
              %{"value" => to_string(user1.id)},
              %{"value" => to_string(user2.id)}
            ]
          }
        ]
      }

      conn = patch(conn, "/#{organization.slug}/scim/v2/Groups/#{group.id}", patch_ops)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert length(response["members"]) == 2
      member_ids = Enum.map(response["members"], & &1["value"])
      assert to_string(user1.id) in member_ids
      assert to_string(user2.id) in member_ids
    end

    test "removes member from group", %{conn: conn, organization: organization} do
      {:ok, group} =
        Accounts.create_group(%{name: "Engineering", organization_id: organization.id})

      user1 = user_fixture(organization: organization, email: "user1@example.com")
      user2 = user_fixture(organization: organization, email: "user2@example.com")

      {:ok, _} = Accounts.add_user_to_group(user1, group)
      {:ok, _} = Accounts.add_user_to_group(user2, group)

      patch_ops = %{
        "Operations" => [
          %{
            "op" => "remove",
            "path" => "members[value eq \"#{user1.id}\"]"
          }
        ]
      }

      conn = patch(conn, "/#{organization.slug}/scim/v2/Groups/#{group.id}", patch_ops)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert length(response["members"]) == 1
      member_ids = Enum.map(response["members"], & &1["value"])
      refute to_string(user1.id) in member_ids
      assert to_string(user2.id) in member_ids
    end

    test "returns error when adding non-existent user", %{conn: conn, organization: organization} do
      {:ok, group} =
        Accounts.create_group(%{name: "Engineering", organization_id: organization.id})

      patch_ops = %{
        "Operations" => [
          %{
            "op" => "add",
            "path" => "members",
            "value" => [
              %{"value" => "99999"}
            ]
          }
        ]
      }

      conn = patch(conn, "/#{organization.slug}/scim/v2/Groups/#{group.id}", patch_ops)

      assert conn.status == 400
      response = json_response(conn, 400)
      assert response["detail"] =~ "not found"
    end

    test "returns error when adding user from different organization", %{
      conn: conn,
      organization: organization
    } do
      {:ok, group} =
        Accounts.create_group(%{name: "Engineering", organization_id: organization.id})

      other_org = organization_fixture()
      other_user = user_fixture(organization: other_org, email: "other@example.com")

      patch_ops = %{
        "Operations" => [
          %{
            "op" => "add",
            "path" => "members",
            "value" => [
              %{"value" => to_string(other_user.id)}
            ]
          }
        ]
      }

      conn = patch(conn, "/#{organization.slug}/scim/v2/Groups/#{group.id}", patch_ops)

      assert conn.status == 400
      response = json_response(conn, 400)
      assert response["detail"] =~ "does not belong to this organization"
    end

    test "returns error for unsupported operation", %{conn: conn, organization: organization} do
      {:ok, group} =
        Accounts.create_group(%{name: "Engineering", organization_id: organization.id})

      patch_ops = %{
        "Operations" => [
          %{
            "op" => "invalid",
            "path" => "displayName",
            "value" => "New Name"
          }
        ]
      }

      conn = patch(conn, "/#{organization.slug}/scim/v2/Groups/#{group.id}", patch_ops)

      assert conn.status == 400
      response = json_response(conn, 400)
      assert response["detail"] =~ "Unsupported PATCH operation"
    end

    test "requires scim:groups:write scope", %{conn: conn, organization: organization} do
      {:ok, group} =
        Accounts.create_group(%{name: "Engineering", organization_id: organization.id})

      conn =
        conn
        |> assign(:current_scopes, ["scim:read"])

      patch_ops = %{
        "Operations" => [
          %{
            "op" => "replace",
            "path" => "displayName",
            "value" => "New Name"
          }
        ]
      }

      conn = patch(conn, "/#{organization.slug}/scim/v2/Groups/#{group.id}", patch_ops)

      assert conn.status == 403
    end
  end

  describe "DELETE /scim/v2/Groups/:id" do
    test "deletes a group", %{conn: conn, organization: organization} do
      {:ok, group} =
        Accounts.create_group(%{name: "Engineering", organization_id: organization.id})

      conn = delete(conn, "/#{organization.slug}/scim/v2/Groups/#{group.id}")

      assert conn.status == 204
      assert conn.resp_body == ""

      # Verify group is deleted
      assert Accounts.get_group(group.id) == nil
    end

    test "returns 404 for non-existent group", %{conn: conn, organization: organization} do
      conn = delete(conn, "/#{organization.slug}/scim/v2/Groups/99999")

      assert conn.status == 404
    end

    test "returns 404 for group from different organization", %{
      conn: conn,
      organization: organization
    } do
      other_org = organization_fixture()
      {:ok, group} = Accounts.create_group(%{name: "Other Group", organization_id: other_org.id})

      conn = delete(conn, "/#{organization.slug}/scim/v2/Groups/#{group.id}")

      assert conn.status == 404
    end

    test "requires scim:groups:write scope", %{conn: conn, organization: organization} do
      {:ok, group} =
        Accounts.create_group(%{name: "Engineering", organization_id: organization.id})

      conn =
        conn
        |> assign(:current_scopes, ["scim:read"])

      conn = delete(conn, "/#{organization.slug}/scim/v2/Groups/#{group.id}")

      assert conn.status == 403
    end
  end

  describe "multi-tenant isolation" do
    test "cannot list groups from other organizations", %{conn: conn} do
      org1 = organization_fixture()
      org2 = organization_fixture()

      {:ok, _} = Accounts.create_group(%{name: "Org1 Group", organization_id: org1.id})
      {:ok, _} = Accounts.create_group(%{name: "Org2 Group", organization_id: org2.id})

      conn = assign(conn, :current_organization, org1)
      conn = get(conn, "/#{org1.slug}/scim/v2/Groups")

      response = json_response(conn, 200)
      group_names = Enum.map(response["Resources"], & &1["displayName"])

      assert "Org1 Group" in group_names
      refute "Org2 Group" in group_names
    end
  end
end
