defmodule AuthifyWeb.SCIM.MeControllerTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  alias Authify.Accounts

  setup %{conn: conn} do
    organization = organization_fixture()
    user = user_fixture(organization: organization, email: "me@example.com")

    conn =
      conn
      |> assign(:current_organization, organization)
      |> assign(:current_user, user)
      |> assign(:api_authenticated, true)
      |> assign(:current_scopes, ["scim:me", "scim:me:write"])

    {:ok, conn: conn, organization: organization, user: user}
  end

  describe "GET /scim/v2/Me" do
    test "returns authenticated user's SCIM resource", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      conn = get(conn, "/#{organization.slug}/scim/v2/Me")

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == ["application/scim+json; charset=utf-8"]

      response = json_response(conn, 200)

      # Verify it's the authenticated user
      assert response["id"] == to_string(user.id)
      assert response["userName"] == user.username

      # Verify SCIM resource format
      assert response["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:User"]
      assert response["meta"]["resourceType"] == "User"
      assert response["meta"]["location"]

      # Verify ETag header
      assert get_resp_header(conn, "etag") != []
    end

    test "requires scim:me scope", %{conn: conn, organization: organization} do
      conn =
        conn
        |> assign(:current_scopes, ["some:other:scope"])
        |> get("/#{organization.slug}/scim/v2/Me")

      assert conn.status == 403
      response = json_response(conn, 403)
      assert response["scimType"] == "sensitive"
    end

    test "allows scim:users:read scope", %{conn: conn, organization: organization} do
      conn =
        conn
        |> assign(:current_scopes, ["scim:users:read"])
        |> get("/#{organization.slug}/scim/v2/Me")

      assert conn.status == 200
    end

    test "allows scim:read scope", %{conn: conn, organization: organization} do
      conn =
        conn
        |> assign(:current_scopes, ["scim:read"])
        |> get("/#{organization.slug}/scim/v2/Me")

      assert conn.status == 200
    end

    test "returns 401 if user not authenticated", %{conn: conn, organization: organization} do
      conn =
        conn
        |> assign(:current_user, nil)
        |> get("/#{organization.slug}/scim/v2/Me")

      assert conn.status == 401
      response = json_response(conn, 401)
      assert response["detail"] == "Authentication required"
    end

    test "includes user groups in response", %{conn: conn, organization: organization, user: user} do
      group = group_fixture(organization: organization, name: "Test Group")
      Accounts.add_user_to_group(user, group)

      conn = get(conn, "/#{organization.slug}/scim/v2/Me")

      response = json_response(conn, 200)
      refute Enum.empty?(response["groups"])
      group_ids = Enum.map(response["groups"], & &1["value"])
      assert to_string(group.id) in group_ids
    end
  end

  describe "PUT /scim/v2/Me" do
    test "updates authenticated user's resource", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      update_params = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => user.username,
        "emails" => [%{"value" => "updated@example.com", "primary" => true}],
        "name" => %{"givenName" => "Updated", "familyName" => "Name"},
        "active" => true
      }

      conn = put(conn, "/#{organization.slug}/scim/v2/Me", update_params)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["id"] == to_string(user.id)
      assert response["name"]["givenName"] == "Updated"
      assert response["name"]["familyName"] == "Name"

      # Verify database was updated
      updated_user = Accounts.get_user(user.id)
      assert updated_user.first_name == "Updated"
      assert updated_user.last_name == "Name"
    end

    test "requires scim:me:write scope", %{conn: conn, organization: organization, user: user} do
      conn =
        conn
        |> assign(:current_scopes, ["scim:me"])
        |> put("/#{organization.slug}/scim/v2/Me", %{
          "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
          "userName" => user.username,
          "active" => true
        })

      assert conn.status == 403
    end

    test "allows scim:users:write scope", %{conn: conn, organization: organization, user: user} do
      conn =
        conn
        |> assign(:current_scopes, ["scim:users:write"])
        |> put("/#{organization.slug}/scim/v2/Me", %{
          "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
          "userName" => user.username,
          "emails" => [%{"value" => "test@example.com", "primary" => true}],
          "active" => true
        })

      assert conn.status == 200
    end

    test "allows scim:write scope", %{conn: conn, organization: organization, user: user} do
      conn =
        conn
        |> assign(:current_scopes, ["scim:write"])
        |> put("/#{organization.slug}/scim/v2/Me", %{
          "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
          "userName" => user.username,
          "emails" => [%{"value" => "test@example.com", "primary" => true}],
          "active" => true
        })

      assert conn.status == 200
    end

    test "validates immutable externalId field", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      # Set initial external_id
      {:ok, user} = Accounts.update_user_scim(user, %{external_id: "original123"})

      update_params = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => user.username,
        "externalId" => "changed456",
        "emails" => [%{"value" => "test@example.com", "primary" => true}],
        "active" => true
      }

      conn =
        conn
        |> assign(:current_user, user)
        |> put("/#{organization.slug}/scim/v2/Me", update_params)

      assert conn.status == 400
      response = json_response(conn, 400)
      assert response["scimType"] == "mutability"
    end

    test "supports If-Match for optimistic locking", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      # Set a specific timestamp for testing
      past_time = DateTime.add(DateTime.utc_now(), -3600, :second)
      {:ok, user} = Accounts.update_user_scim(user, %{active: true, scim_updated_at: past_time})

      # Reload conn with timestamped user
      conn = assign(conn, :current_user, user)

      # Get current ETag (will be based on past_time)
      conn_get = get(conn, "/#{organization.slug}/scim/v2/Me")
      [etag] = get_resp_header(conn_get, "etag")

      # Update will generate new timestamp (current time), making ETag match succeed
      conn =
        conn
        |> put_req_header("if-match", etag)
        |> put("/#{organization.slug}/scim/v2/Me", %{
          "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
          "userName" => "updated_username",
          "emails" => [%{"value" => "test@example.com", "primary" => true}],
          "active" => true
        })

      assert conn.status == 200
    end

    test "returns 412 on ETag mismatch", %{conn: conn, organization: organization, user: user} do
      wrong_etag = "W/\"999-1234567890-abcdef\""

      conn =
        conn
        |> put_req_header("if-match", wrong_etag)
        |> put("/#{organization.slug}/scim/v2/Me", %{
          "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
          "userName" => user.username,
          "emails" => [%{"value" => "test@example.com", "primary" => true}],
          "active" => true
        })

      assert conn.status == 412
    end
  end

  describe "PATCH /scim/v2/Me" do
    test "partially updates authenticated user", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      patch_params = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations" => [
          %{
            "op" => "replace",
            "path" => "name.givenName",
            "value" => "Patched"
          }
        ]
      }

      conn = patch(conn, "/#{organization.slug}/scim/v2/Me", patch_params)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["id"] == to_string(user.id)
      assert response["name"]["givenName"] == "Patched"

      # Verify database was updated
      updated_user = Accounts.get_user(user.id)
      assert updated_user.first_name == "Patched"
    end

    test "requires scim:me:write scope", %{conn: conn, organization: organization} do
      conn =
        conn
        |> assign(:current_scopes, ["scim:me"])
        |> patch("/#{organization.slug}/scim/v2/Me", %{
          "schemas" => ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          "Operations" => [%{"op" => "replace", "path" => "active", "value" => false}]
        })

      assert conn.status == 403
    end

    test "allows scim:users:write scope", %{conn: conn, organization: organization} do
      conn =
        conn
        |> assign(:current_scopes, ["scim:users:write"])
        |> patch("/#{organization.slug}/scim/v2/Me", %{
          "schemas" => ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          "Operations" => [%{"op" => "replace", "path" => "active", "value" => false}]
        })

      assert conn.status == 200
    end

    test "supports multiple operations", %{conn: conn, organization: organization} do
      patch_params = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations" => [
          %{"op" => "replace", "path" => "name.givenName", "value" => "First"},
          %{"op" => "replace", "path" => "name.familyName", "value" => "Last"}
        ]
      }

      conn = patch(conn, "/#{organization.slug}/scim/v2/Me", patch_params)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["name"]["givenName"] == "First"
      assert response["name"]["familyName"] == "Last"
    end

    test "returns error for invalid operations", %{conn: conn, organization: organization} do
      invalid_params = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations" => [
          %{
            "op" => "invalid_op",
            "path" => "active",
            "value" => false
          }
        ]
      }

      conn = patch(conn, "/#{organization.slug}/scim/v2/Me", invalid_params)

      assert conn.status == 400
    end
  end

  describe "scope hierarchy" do
    test "scim:me:write includes scim:me", %{conn: conn, organization: organization} do
      # User with only scim:me:write can read their own resource
      conn =
        conn
        |> assign(:current_scopes, ["scim:me:write"])
        |> get("/#{organization.slug}/scim/v2/Me")

      assert conn.status == 200
    end

    test "scim:users:read includes scim:me", %{conn: conn, organization: organization} do
      conn =
        conn
        |> assign(:current_scopes, ["scim:users:read"])
        |> get("/#{organization.slug}/scim/v2/Me")

      assert conn.status == 200
    end

    test "scim:users:write includes scim:me and scim:me:write", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      # Can read
      conn_read =
        conn
        |> assign(:current_scopes, ["scim:users:write"])
        |> get("/#{organization.slug}/scim/v2/Me")

      assert conn_read.status == 200

      # Can write
      conn_write =
        conn
        |> assign(:current_scopes, ["scim:users:write"])
        |> put("/#{organization.slug}/scim/v2/Me", %{
          "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
          "userName" => user.username,
          "emails" => [%{"value" => "test@example.com", "primary" => true}],
          "active" => true
        })

      assert conn_write.status == 200
    end

    test "scim:read includes scim:me", %{conn: conn, organization: organization} do
      conn =
        conn
        |> assign(:current_scopes, ["scim:read"])
        |> get("/#{organization.slug}/scim/v2/Me")

      assert conn.status == 200
    end

    test "scim:write includes scim:me:write", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      conn =
        conn
        |> assign(:current_scopes, ["scim:write"])
        |> put("/#{organization.slug}/scim/v2/Me", %{
          "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
          "userName" => user.username,
          "emails" => [%{"value" => "test@example.com", "primary" => true}],
          "active" => true
        })

      assert conn.status == 200
    end
  end
end
