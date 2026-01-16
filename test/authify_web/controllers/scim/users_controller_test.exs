defmodule AuthifyWeb.SCIM.UsersControllerTest do
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

  describe "GET /scim/v2/Users" do
    test "returns list of users with pagination", %{conn: conn, organization: organization} do
      # Create test users
      user1 = user_fixture(organization: organization, email: "alice@example.com")
      user2 = user_fixture(organization: organization, email: "bob@example.com")

      conn = get(conn, "/#{organization.slug}/scim/v2/Users")

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == ["application/scim+json; charset=utf-8"]

      response = json_response(conn, 200)

      # Verify ListResponse format
      assert response["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
      assert response["totalResults"] >= 2
      assert response["startIndex"] == 1
      assert is_list(response["Resources"])

      # Verify user resources contain expected fields
      user_ids = Enum.map(response["Resources"], & &1["id"])
      assert to_string(user1.id) in user_ids
      assert to_string(user2.id) in user_ids
    end

    test "supports pagination with startIndex and count", %{
      conn: conn,
      organization: organization
    } do
      # Create 5 users
      Enum.each(1..5, fn i ->
        user_fixture(organization: organization, email: "user#{i}@example.com")
      end)

      # Get first page
      conn = get(conn, "/#{organization.slug}/scim/v2/Users?startIndex=1&count=2")
      response = json_response(conn, 200)

      assert response["startIndex"] == 1
      assert response["itemsPerPage"] == 2
      assert length(response["Resources"]) == 2

      # Get second page
      conn = build_conn()
      conn = assign(conn, :current_organization, organization)
      conn = assign(conn, :api_authenticated, true)
      conn = assign(conn, :current_scopes, ["scim:read"])

      conn = get(conn, "/#{organization.slug}/scim/v2/Users?startIndex=3&count=2")
      response = json_response(conn, 200)

      assert response["startIndex"] == 3
      assert response["itemsPerPage"] == 2
    end

    test "respects max count of 100", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/scim/v2/Users?count=200")
      response = json_response(conn, 200)

      # itemsPerPage should be capped at 100 or the actual number of users, whichever is less
      assert response["itemsPerPage"] <= 100
    end

    test "filters users by userName", %{conn: conn, organization: organization} do
      user =
        user_fixture(organization: organization, username: "jsmith", email: "jsmith@example.com")

      _other =
        user_fixture(organization: organization, username: "bjones", email: "bjones@example.com")

      conn = get(conn, "/#{organization.slug}/scim/v2/Users?filter=userName eq \"jsmith\"")
      response = json_response(conn, 200)

      assert response["totalResults"] == 1
      assert length(response["Resources"]) == 1
      assert hd(response["Resources"])["id"] == to_string(user.id)
      assert hd(response["Resources"])["userName"] == "jsmith"
    end

    test "filters users by email", %{conn: conn, organization: organization} do
      user = user_fixture(organization: organization, email: "alice@example.com")
      _other = user_fixture(organization: organization, email: "bob@example.com")

      conn =
        get(conn, "/#{organization.slug}/scim/v2/Users?filter=emails eq \"alice@example.com\"")

      response = json_response(conn, 200)

      assert response["totalResults"] == 1
      assert hd(response["Resources"])["id"] == to_string(user.id)
    end

    test "filters users by active status", %{conn: conn, organization: organization} do
      active_user = user_fixture(organization: organization, active: true)
      _inactive_user = user_fixture(organization: organization, active: false)

      conn = get(conn, "/#{organization.slug}/scim/v2/Users?filter=active eq true")
      response = json_response(conn, 200)

      user_ids = Enum.map(response["Resources"], & &1["id"])
      assert to_string(active_user.id) in user_ids
    end

    test "returns error for invalid filter", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/scim/v2/Users?filter=invalidField eq \"value\"")

      assert conn.status == 400
      response = json_response(conn, 400)

      assert response["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
      assert response["scimType"] == "invalidFilter"
    end

    test "requires scim:users:read scope", %{conn: conn, organization: organization} do
      conn =
        conn
        |> assign(:current_scopes, ["other:scope"])

      conn = get(conn, "/#{organization.slug}/scim/v2/Users")

      assert conn.status == 403
      response = json_response(conn, 403)
      assert response["scimType"] == "sensitive"
    end

    test "allows scim:read scope", %{conn: conn, organization: organization} do
      conn =
        conn
        |> assign(:current_scopes, ["scim:read"])

      conn = get(conn, "/#{organization.slug}/scim/v2/Users")

      assert conn.status == 200
    end
  end

  describe "GET /scim/v2/Users/:id" do
    test "returns a single user", %{conn: conn, organization: organization} do
      user =
        user_fixture(
          organization: organization,
          username: "jsmith",
          email: "jsmith@example.com",
          first_name: "John",
          last_name: "Smith",
          external_id: "ext-123"
        )

      conn = get(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}")

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:User"]
      assert response["id"] == to_string(user.id)
      assert response["externalId"] == "ext-123"
      assert response["userName"] == "jsmith"
      assert response["name"]["givenName"] == "John"
      assert response["name"]["familyName"] == "Smith"

      assert response["emails"] == [
               %{"value" => "jsmith@example.com", "primary" => true, "type" => "work"}
             ]

      assert response["active"] == true
      assert is_map(response["meta"])
      assert response["meta"]["resourceType"] == "User"
    end

    test "includes groups in user response", %{conn: conn, organization: organization} do
      user = user_fixture(organization: organization)
      group = group_fixture(organization: organization, name: "Engineering")
      Accounts.add_user_to_group(user, group)

      conn = get(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}")
      response = json_response(conn, 200)

      assert is_list(response["groups"])
      assert length(response["groups"]) == 1
      assert hd(response["groups"])["display"] == "Engineering"
      assert hd(response["groups"])["value"] == to_string(group.id)
    end

    test "returns 404 for non-existent user", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/scim/v2/Users/99999")

      assert conn.status == 404
      response = json_response(conn, 404)

      assert response["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
      assert response["status"] == "404"
      assert response["scimType"] == "noTarget"
    end

    test "returns 404 for user from different organization", %{
      conn: conn,
      organization: organization
    } do
      other_org = organization_fixture()
      other_user = user_fixture(organization: other_org)

      conn = get(conn, "/#{organization.slug}/scim/v2/Users/#{other_user.id}")

      assert conn.status == 404
      response = json_response(conn, 404)
      assert response["scimType"] == "noTarget"
    end

    test "requires scim:users:read scope", %{conn: conn, organization: organization} do
      user = user_fixture(organization: organization)

      conn =
        conn
        |> assign(:current_scopes, ["other:scope"])

      conn = get(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}")

      assert conn.status == 403
    end
  end

  describe "POST /scim/v2/Users" do
    test "creates a new user with SCIM attributes", %{conn: conn, organization: organization} do
      params = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => "jdoe",
        "externalId" => "hr-12345",
        "name" => %{
          "givenName" => "Jane",
          "familyName" => "Doe"
        },
        "emails" => [
          %{"value" => "jdoe@example.com", "primary" => true}
        ],
        "active" => true
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Users", params)

      assert conn.status == 201
      response = json_response(conn, 201)

      assert response["userName"] == "jdoe"
      assert response["externalId"] == "hr-12345"
      assert response["name"]["givenName"] == "Jane"
      assert response["name"]["familyName"] == "Doe"
      assert response["active"] == true

      # Verify Location header
      location = get_resp_header(conn, "location")
      assert length(location) == 1
      assert String.contains?(hd(location), "/Users/#{response["id"]}")

      # Verify user was created in database
      user = Accounts.get_user(String.to_integer(response["id"]))
      assert user.username == "jdoe"
      assert user.external_id == "hr-12345"
      assert user.first_name == "Jane"
      assert user.last_name == "Doe"
      assert Authify.Accounts.User.get_primary_email_value(user) == "jdoe@example.com"
      assert user.organization_id == organization.id
    end

    test "uses userName as email when it contains @", %{conn: conn, organization: organization} do
      params = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => "jane@example.com",
        "name" => %{
          "givenName" => "Jane",
          "familyName" => "Doe"
        }
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Users", params)

      assert conn.status == 201
      response = json_response(conn, 201)

      user = Accounts.get_user(String.to_integer(response["id"]))
      assert Authify.Accounts.User.get_primary_email_value(user) == "jane@example.com"
    end

    test "uses userName as username when it doesn't contain @", %{
      conn: conn,
      organization: organization
    } do
      params = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => "jdoe",
        "emails" => [%{"value" => "jdoe@example.com"}]
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Users", params)

      assert conn.status == 201
      response = json_response(conn, 201)

      user = Accounts.get_user(String.to_integer(response["id"]))
      assert user.username == "jdoe"
      assert Authify.Accounts.User.get_primary_email_value(user) == "jdoe@example.com"
    end

    test "uses primary email when multiple emails provided", %{
      conn: conn,
      organization: organization
    } do
      params = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => "jdoe",
        "emails" => [
          %{"value" => "work@example.com", "type" => "work", "primary" => false},
          %{"value" => "primary@example.com", "type" => "work", "primary" => true},
          %{"value" => "other@example.com", "type" => "home", "primary" => false}
        ]
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Users", params)

      assert conn.status == 201
      response = json_response(conn, 201)

      user = Accounts.get_user(String.to_integer(response["id"]))
      assert Authify.Accounts.User.get_primary_email_value(user) == "primary@example.com"
    end

    test "returns 409 for duplicate externalId", %{conn: conn, organization: organization} do
      # Create user with externalId
      _existing = user_fixture(organization: organization, external_id: "hr-12345")

      params = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => "different",
        "externalId" => "hr-12345",
        "emails" => [%{"value" => "different@example.com"}]
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Users", params)

      assert conn.status == 409
      response = json_response(conn, 409)

      assert response["scimType"] == "uniqueness"
      assert String.contains?(response["detail"], "hr-12345")
    end

    test "returns 409 for duplicate email", %{conn: conn, organization: organization} do
      _existing = user_fixture(organization: organization, email: "existing@example.com")

      params = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => "newuser",
        "emails" => [%{"value" => "existing@example.com"}]
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Users", params)

      assert conn.status == 409
      response = json_response(conn, 409)

      assert response["scimType"] == "uniqueness"
      assert String.contains?(response["detail"], "existing@example.com")
    end

    test "returns 409 for duplicate userName", %{conn: conn, organization: organization} do
      _existing = user_fixture(organization: organization, username: "jsmith")

      params = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => "jsmith",
        "emails" => [%{"value" => "different@example.com"}]
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Users", params)

      assert conn.status == 409
      response = json_response(conn, 409)

      assert response["scimType"] == "uniqueness"
    end

    test "requires scim:users:write scope", %{conn: conn, organization: organization} do
      conn =
        conn
        |> assign(:current_scopes, ["scim:read"])

      params = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => "jdoe",
        "emails" => [%{"value" => "jdoe@example.com"}]
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Users", params)

      assert conn.status == 403
    end

    test "allows scim:write scope", %{conn: conn, organization: organization} do
      conn =
        conn
        |> assign(:current_scopes, ["scim:write"])

      params = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => "jdoe@example.com",
        "emails" => [%{"value" => "jdoe@example.com"}]
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Users", params)

      assert conn.status == 201
    end
  end

  describe "PUT /scim/v2/Users/:id" do
    test "updates a user with full replacement", %{conn: conn, organization: organization} do
      user =
        user_fixture(
          organization: organization,
          username: "oldname",
          first_name: "Old",
          last_name: "Name"
        )

      params = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => "newname",
        "name" => %{
          "givenName" => "New",
          "familyName" => "Name"
        },
        "emails" => [%{"value" => "newname@example.com"}],
        "active" => false
      }

      conn = put(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}", params)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["userName"] == "newname"
      assert response["name"]["givenName"] == "New"
      assert response["active"] == false

      # Verify database update
      updated_user = Accounts.get_user(user.id)
      assert updated_user.first_name == "New"
      assert updated_user.active == false
    end

    test "prevents modification of immutable externalId", %{
      conn: conn,
      organization: organization
    } do
      user = user_fixture(organization: organization, external_id: "original-id")

      params = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => "updated",
        "externalId" => "new-id",
        "emails" => [%{"value" => "updated@example.com"}]
      }

      conn = put(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}", params)

      assert conn.status == 400
      response = json_response(conn, 400)

      assert response["scimType"] == "mutability"
      assert String.contains?(response["detail"], "externalId")
    end

    test "returns 404 for non-existent user", %{conn: conn, organization: organization} do
      params = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => "test"
      }

      conn = put(conn, "/#{organization.slug}/scim/v2/Users/99999", params)

      assert conn.status == 404
    end

    test "returns 404 for user from different organization", %{
      conn: conn,
      organization: organization
    } do
      other_org = organization_fixture()
      other_user = user_fixture(organization: other_org)

      params = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => "test"
      }

      conn = put(conn, "/#{organization.slug}/scim/v2/Users/#{other_user.id}", params)

      assert conn.status == 404
    end

    test "requires scim:users:write scope", %{conn: conn, organization: organization} do
      user = user_fixture(organization: organization)

      conn =
        conn
        |> assign(:current_scopes, ["scim:read"])

      params = %{"userName" => "test"}

      conn = put(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}", params)

      assert conn.status == 403
    end
  end

  describe "PATCH /scim/v2/Users/:id" do
    test "applies replace operation to active field", %{conn: conn, organization: organization} do
      user = user_fixture(organization: organization, active: true)

      params = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations" => [
          %{"op" => "replace", "path" => "active", "value" => false}
        ]
      }

      conn = patch(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}", params)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["active"] == false

      updated_user = Accounts.get_user(user.id)
      assert updated_user.active == false
    end

    test "applies replace operation to name.givenName", %{
      conn: conn,
      organization: organization
    } do
      user = user_fixture(organization: organization, first_name: "John")

      params = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations" => [
          %{"op" => "replace", "path" => "name.givenName", "value" => "Jane"}
        ]
      }

      conn = patch(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}", params)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["name"]["givenName"] == "Jane"
    end

    test "applies replace operation to name.familyName", %{
      conn: conn,
      organization: organization
    } do
      user = user_fixture(organization: organization, last_name: "Smith")

      params = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations" => [
          %{"op" => "replace", "path" => "name.familyName", "value" => "Doe"}
        ]
      }

      conn = patch(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}", params)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["name"]["familyName"] == "Doe"
    end

    test "applies replace operation with no path (full resource)", %{
      conn: conn,
      organization: organization
    } do
      user = user_fixture(organization: organization)

      params = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations" => [
          %{
            "op" => "replace",
            "value" => %{
              "userName" => "updated@example.com",
              "name" => %{"givenName" => "Updated", "familyName" => "User"},
              "active" => false
            }
          }
        ]
      }

      conn = patch(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}", params)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["name"]["givenName"] == "Updated"
      assert response["active"] == false
    end

    test "applies multiple operations in sequence", %{conn: conn, organization: organization} do
      user = user_fixture(organization: organization, first_name: "John", active: true)

      params = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations" => [
          %{"op" => "replace", "path" => "name.givenName", "value" => "Jane"},
          %{"op" => "replace", "path" => "active", "value" => false}
        ]
      }

      conn = patch(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}", params)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["name"]["givenName"] == "Jane"
      assert response["active"] == false
    end

    test "returns error for unsupported path", %{conn: conn, organization: organization} do
      user = user_fixture(organization: organization)

      params = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations" => [
          %{"op" => "replace", "path" => "unsupported.field", "value" => "test"}
        ]
      }

      conn = patch(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}", params)

      assert conn.status == 400
      response = json_response(conn, 400)

      assert response["scimType"] == "invalidValue"
    end

    test "returns error for unsupported operation", %{conn: conn, organization: organization} do
      user = user_fixture(organization: organization)

      params = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations" => [
          %{"op" => "add", "path" => "emails", "value" => "new@example.com"}
        ]
      }

      conn = patch(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}", params)

      assert conn.status == 400
      response = json_response(conn, 400)

      assert response["scimType"] == "invalidValue"
    end

    test "returns 404 for non-existent user", %{conn: conn, organization: organization} do
      params = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations" => [%{"op" => "replace", "path" => "active", "value" => false}]
      }

      conn = patch(conn, "/#{organization.slug}/scim/v2/Users/99999", params)

      assert conn.status == 404
    end

    test "requires scim:users:write scope", %{conn: conn, organization: organization} do
      user = user_fixture(organization: organization)

      conn =
        conn
        |> assign(:current_scopes, ["scim:read"])

      params = %{
        "Operations" => [%{"op" => "replace", "path" => "active", "value" => false}]
      }

      conn = patch(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}", params)

      assert conn.status == 403
    end
  end

  describe "DELETE /scim/v2/Users/:id" do
    test "soft deletes a user (sets active=false)", %{conn: conn, organization: organization} do
      user = user_fixture(organization: organization, active: true)

      conn = delete(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}")

      assert conn.status == 204
      assert conn.resp_body == ""

      # Verify user is deactivated, not deleted
      updated_user = Accounts.get_user(user.id)
      assert updated_user != nil
      assert updated_user.active == false
    end

    test "returns 404 for non-existent user", %{conn: conn, organization: organization} do
      conn = delete(conn, "/#{organization.slug}/scim/v2/Users/99999")

      assert conn.status == 404
    end

    test "returns 404 for user from different organization", %{
      conn: conn,
      organization: organization
    } do
      other_org = organization_fixture()
      other_user = user_fixture(organization: other_org)

      conn = delete(conn, "/#{organization.slug}/scim/v2/Users/#{other_user.id}")

      assert conn.status == 404
    end

    test "requires scim:users:write scope", %{conn: conn, organization: organization} do
      user = user_fixture(organization: organization)

      conn =
        conn
        |> assign(:current_scopes, ["scim:read"])

      conn = delete(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}")

      assert conn.status == 403
    end
  end
end
