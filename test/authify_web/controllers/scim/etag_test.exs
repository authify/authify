defmodule AuthifyWeb.SCIM.ETagTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  alias Authify.Accounts
  alias Authify.SCIM.Version

  setup %{conn: conn} do
    organization = organization_fixture()
    admin_user = user_fixture(organization: organization, role: "admin")

    conn =
      conn
      |> assign(:current_organization, organization)
      |> assign(:current_user, admin_user)
      |> assign(:actor_type, :user)
      |> assign(:api_authenticated, true)
      |> assign(:current_scopes, ["scim:read", "scim:write"])

    {:ok, conn: conn, organization: organization, admin_user: admin_user}
  end

  describe "ETag support for Users" do
    test "GET /scim/v2/Users/:id returns ETag header", %{conn: conn, organization: organization} do
      user = user_fixture(organization: organization, email: "test@example.com")

      conn = get(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}")

      assert conn.status == 200
      etag_headers = get_resp_header(conn, "etag")
      assert length(etag_headers) == 1
      [etag] = etag_headers

      # Verify weak ETag format
      assert String.starts_with?(etag, "W/\"")
      assert String.ends_with?(etag, "\"")

      # Verify version in response meta
      response = json_response(conn, 200)
      assert response["meta"]["version"] != nil
      version = response["meta"]["version"]

      # ETag should contain the version (without W/ prefix)
      assert etag == "W/\"#{version}\""
    end

    test "POST /scim/v2/Users returns ETag header for created user", %{
      conn: conn,
      organization: organization
    } do
      user_params = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => "newuser",
        "emails" => [%{"value" => "newuser@example.com", "primary" => true}],
        "active" => true
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Users", user_params)

      assert conn.status == 201
      etag_headers = get_resp_header(conn, "etag")
      assert length(etag_headers) == 1
      [etag] = etag_headers
      assert String.starts_with?(etag, "W/\"")

      response = json_response(conn, 201)
      assert response["meta"]["version"] != nil
    end

    test "PUT /scim/v2/Users/:id returns updated ETag", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      user = user_fixture(organization: organization, email: "test@example.com")

      # Get initial ETag
      conn = get(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}")
      initial_response = json_response(conn, 200)
      initial_version = initial_response["meta"]["version"]

      # Wait to ensure Unix timestamp changes (must be at least 1 second)
      Process.sleep(1100)

      # Update the user
      conn = build_conn()
      conn = assign(conn, :current_organization, organization)
      conn = assign(conn, :current_user, admin_user)
      conn = assign(conn, :actor_type, :user)
      conn = assign(conn, :api_authenticated, true)
      conn = assign(conn, :current_scopes, ["scim:write"])

      update_params = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => user.username,
        "emails" => [%{"value" => "updated@example.com", "primary" => true}],
        "active" => true
      }

      conn = put(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}", update_params)

      assert conn.status == 200
      updated_response = json_response(conn, 200)
      updated_version = updated_response["meta"]["version"]

      # Version should change after update
      assert updated_version != initial_version
    end

    test "PATCH /scim/v2/Users/:id returns updated ETag", %{
      conn: conn,
      organization: organization
    } do
      user = user_fixture(organization: organization, email: "test@example.com")

      patch_params = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations" => [
          %{
            "op" => "replace",
            "path" => "active",
            "value" => false
          }
        ]
      }

      conn = patch(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}", patch_params)

      assert conn.status == 200
      etag_headers = get_resp_header(conn, "etag")
      assert length(etag_headers) == 1

      response = json_response(conn, 200)
      assert response["meta"]["version"] != nil
    end

    test "If-None-Match returns 304 when ETag matches", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      user = user_fixture(organization: organization, email: "test@example.com")

      # Get the resource and its ETag
      conn = get(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}")
      [etag] = get_resp_header(conn, "etag")

      # Make a new request with If-None-Match
      conn = build_conn()
      conn = assign(conn, :current_organization, organization)
      conn = assign(conn, :current_user, admin_user)
      conn = assign(conn, :actor_type, :user)
      conn = assign(conn, :api_authenticated, true)
      conn = assign(conn, :current_scopes, ["scim:read"])

      conn =
        conn
        |> put_req_header("if-none-match", etag)
        |> get("/#{organization.slug}/scim/v2/Users/#{user.id}")

      # Should return 304 Not Modified
      assert conn.status == 304
      assert conn.resp_body == ""
    end

    test "If-None-Match returns 200 when ETag differs", %{
      conn: conn,
      organization: organization
    } do
      user = user_fixture(organization: organization, email: "test@example.com")

      # Use a different ETag
      wrong_etag = "W/\"999-1234567890-abcdef\""

      conn =
        conn
        |> put_req_header("if-none-match", wrong_etag)
        |> get("/#{organization.slug}/scim/v2/Users/#{user.id}")

      # Should return 200 with the resource
      assert conn.status == 200
      response = json_response(conn, 200)
      assert response["id"] == to_string(user.id)
    end

    test "If-Match allows update when ETag matches", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      user = user_fixture(organization: organization, email: "test@example.com")

      # Get current ETag
      conn = get(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}")
      [etag] = get_resp_header(conn, "etag")

      # Update with matching If-Match
      conn = build_conn()
      conn = assign(conn, :current_organization, organization)
      conn = assign(conn, :current_user, admin_user)
      conn = assign(conn, :actor_type, :user)
      conn = assign(conn, :api_authenticated, true)
      conn = assign(conn, :current_scopes, ["scim:write"])

      update_params = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => user.username,
        "emails" => [%{"value" => "updated@example.com", "primary" => true}],
        "active" => true
      }

      conn =
        conn
        |> put_req_header("if-match", etag)
        |> put("/#{organization.slug}/scim/v2/Users/#{user.id}", update_params)

      # Should succeed
      assert conn.status == 200
    end

    test "If-Match returns 412 when ETag mismatches on PUT", %{
      conn: conn,
      organization: organization
    } do
      user = user_fixture(organization: organization, email: "test@example.com")

      # Use wrong ETag
      wrong_etag = "W/\"999-1234567890-abcdef\""

      update_params = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => user.username,
        "emails" => [%{"value" => "updated@example.com", "primary" => true}],
        "active" => true
      }

      conn =
        conn
        |> put_req_header("if-match", wrong_etag)
        |> put("/#{organization.slug}/scim/v2/Users/#{user.id}", update_params)

      # Should return 412 Precondition Failed
      assert conn.status == 412
      response = json_response(conn, 412)
      assert response["status"] == "412"
      assert response["scimType"] == "invalidVers"
    end

    test "If-Match returns 412 when ETag mismatches on PATCH", %{
      conn: conn,
      organization: organization
    } do
      user = user_fixture(organization: organization, email: "test@example.com")

      wrong_etag = "W/\"999-1234567890-abcdef\""

      patch_params = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations" => [
          %{
            "op" => "replace",
            "path" => "active",
            "value" => false
          }
        ]
      }

      conn =
        conn
        |> put_req_header("if-match", wrong_etag)
        |> patch("/#{organization.slug}/scim/v2/Users/#{user.id}", patch_params)

      assert conn.status == 412
      response = json_response(conn, 412)
      assert response["scimType"] == "invalidVers"
    end

    test "If-Match returns 412 when ETag mismatches on DELETE", %{
      conn: conn,
      organization: organization
    } do
      user = user_fixture(organization: organization, email: "test@example.com")

      wrong_etag = "W/\"999-1234567890-abcdef\""

      conn =
        conn
        |> put_req_header("if-match", wrong_etag)
        |> delete("/#{organization.slug}/scim/v2/Users/#{user.id}")

      assert conn.status == 412
      response = json_response(conn, 412)
      assert response["scimType"] == "invalidVers"
    end

    test "concurrent updates trigger 412 correctly", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      user = user_fixture(organization: organization, email: "test@example.com")

      # Initialize scim_updated_at by doing an initial SCIM update
      {:ok, user} = Accounts.update_user_scim(user, %{active: true})

      # Wait to ensure clean timestamp
      Process.sleep(1100)

      # First client gets the resource
      conn1 = get(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}")
      [etag1] = get_resp_header(conn1, "etag")

      # Second client gets the same resource (same ETag)
      conn2 = build_conn()
      conn2 = assign(conn2, :current_organization, organization)
      conn2 = assign(conn2, :current_user, admin_user)
      conn2 = assign(conn2, :actor_type, :user)
      conn2 = assign(conn2, :api_authenticated, true)
      conn2 = assign(conn2, :current_scopes, ["scim:read"])
      conn2 = get(conn2, "/#{organization.slug}/scim/v2/Users/#{user.id}")
      [etag2] = get_resp_header(conn2, "etag")

      assert etag1 == etag2

      # First client updates successfully
      conn1 = build_conn()
      conn1 = assign(conn1, :current_organization, organization)
      conn1 = assign(conn1, :current_user, admin_user)
      conn1 = assign(conn1, :actor_type, :user)
      conn1 = assign(conn1, :api_authenticated, true)
      conn1 = assign(conn1, :current_scopes, ["scim:write"])

      update1 = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => user.username,
        "emails" => [%{"value" => "client1@example.com", "primary" => true}],
        "active" => true
      }

      conn1 =
        conn1
        |> put_req_header("if-match", etag1)
        |> put("/#{organization.slug}/scim/v2/Users/#{user.id}", update1)

      assert conn1.status == 200

      # Wait to ensure timestamp changes (for Unix second precision)
      Process.sleep(1100)

      # Second client tries to update with stale ETag
      conn2 = build_conn()
      conn2 = assign(conn2, :current_organization, organization)
      conn2 = assign(conn2, :current_user, admin_user)
      conn2 = assign(conn2, :actor_type, :user)
      conn2 = assign(conn2, :api_authenticated, true)
      conn2 = assign(conn2, :current_scopes, ["scim:write"])

      update2 = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => user.username,
        "emails" => [%{"value" => "client2@example.com", "primary" => true}],
        "active" => true
      }

      conn2 =
        conn2
        |> put_req_header("if-match", etag2)
        |> put("/#{organization.slug}/scim/v2/Users/#{user.id}", update2)

      # Second client should get 412 because ETag is now stale
      assert conn2.status == 412
    end

    test "version changes after resource modification", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      user = user_fixture(organization: organization, email: "test@example.com")

      # Get initial version
      conn = get(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}")
      initial_response = json_response(conn, 200)
      initial_version = initial_response["meta"]["version"]

      # Wait to ensure Unix timestamp changes
      Process.sleep(1100)

      # Update the user directly via Accounts context
      {:ok, _updated_user} =
        Accounts.update_user_scim(user, %{active: false, scim_updated_at: DateTime.utc_now()})

      # Get new version
      conn = build_conn()
      conn = assign(conn, :current_organization, organization)
      conn = assign(conn, :current_user, admin_user)
      conn = assign(conn, :actor_type, :user)
      conn = assign(conn, :api_authenticated, true)
      conn = assign(conn, :current_scopes, ["scim:read"])

      conn = get(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}")
      new_response = json_response(conn, 200)
      new_version = new_response["meta"]["version"]

      # Version should have changed
      assert new_version != initial_version
    end

    test "ETag format is correct weak ETag", %{conn: conn, organization: organization} do
      user = user_fixture(organization: organization, email: "test@example.com")

      conn = get(conn, "/#{organization.slug}/scim/v2/Users/#{user.id}")
      [etag] = get_resp_header(conn, "etag")

      # Should match pattern: W/"<id>-<timestamp>-<hash>"
      assert Regex.match?(~r/^W\/"[0-9]+-[0-9]+-[0-9a-f]+"$/, etag)
    end
  end

  describe "ETag support for Groups" do
    test "GET /scim/v2/Groups/:id returns ETag header", %{conn: conn, organization: organization} do
      group = group_fixture(organization: organization, name: "Test Group")

      conn = get(conn, "/#{organization.slug}/scim/v2/Groups/#{group.id}")

      assert conn.status == 200
      etag_headers = get_resp_header(conn, "etag")
      assert length(etag_headers) == 1
      [etag] = etag_headers
      assert String.starts_with?(etag, "W/\"")

      response = json_response(conn, 200)
      assert response["meta"]["version"] != nil
    end

    test "POST /scim/v2/Groups returns ETag header", %{conn: conn, organization: organization} do
      group_params = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName" => "New Group"
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Groups", group_params)

      assert conn.status == 201
      etag_headers = get_resp_header(conn, "etag")
      assert length(etag_headers) == 1

      response = json_response(conn, 201)
      assert response["meta"]["version"] != nil
    end

    test "If-Match works for Group updates", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      group = group_fixture(organization: organization, name: "Test Group")

      # Get ETag
      conn = get(conn, "/#{organization.slug}/scim/v2/Groups/#{group.id}")
      [etag] = get_resp_header(conn, "etag")

      # Update with matching ETag
      conn = build_conn()
      conn = assign(conn, :current_organization, organization)
      conn = assign(conn, :current_user, admin_user)
      conn = assign(conn, :actor_type, :user)
      conn = assign(conn, :api_authenticated, true)
      conn = assign(conn, :current_scopes, ["scim:write"])

      update_params = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName" => "Updated Group"
      }

      conn =
        conn
        |> put_req_header("if-match", etag)
        |> put("/#{organization.slug}/scim/v2/Groups/#{group.id}", update_params)

      assert conn.status == 200
    end

    test "If-Match returns 412 for Group with wrong ETag", %{
      conn: conn,
      organization: organization
    } do
      group = group_fixture(organization: organization, name: "Test Group")

      wrong_etag = "W/\"999-1234567890-abcdef\""

      update_params = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName" => "Updated Group"
      }

      conn =
        conn
        |> put_req_header("if-match", wrong_etag)
        |> put("/#{organization.slug}/scim/v2/Groups/#{group.id}", update_params)

      assert conn.status == 412
    end
  end

  describe "ServiceProviderConfig" do
    test "advertises ETag support", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/scim/v2/ServiceProviderConfig")

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["etag"]["supported"] == true
    end
  end

  describe "Version generation" do
    test "generates consistent version for same resource state" do
      # Create a mock resource
      resource = %{
        id: 123,
        scim_updated_at: ~U[2024-01-18 12:00:00Z]
      }

      version1 = Version.generate_version(resource)
      version2 = Version.generate_version(resource)

      assert version1 == version2
    end

    test "generates different versions for different timestamps" do
      resource1 = %{
        id: 123,
        scim_updated_at: ~U[2024-01-18 12:00:00Z]
      }

      resource2 = %{
        id: 123,
        scim_updated_at: ~U[2024-01-18 12:00:01Z]
      }

      version1 = Version.generate_version(resource1)
      version2 = Version.generate_version(resource2)

      assert version1 != version2
    end

    test "parses ETag correctly" do
      etag = ~s(W/"123-1705579200-a1b2c3d4")
      version = Version.parse_etag(etag)

      assert version == "123-1705579200-a1b2c3d4"
    end

    test "parses strong ETag" do
      etag = ~s("123-1705579200-a1b2c3d4")
      version = Version.parse_etag(etag)

      assert version == "123-1705579200-a1b2c3d4"
    end

    test "returns nil for invalid ETag" do
      assert Version.parse_etag("invalid") == nil
      assert Version.parse_etag("") == nil
      assert Version.parse_etag(nil) == nil
    end
  end
end
