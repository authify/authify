defmodule AuthifyWeb.API.ScimClientsControllerTest do
  use AuthifyWeb.ConnCase, async: false

  import Authify.AccountsFixtures
  import Authify.SCIMClientFixtures

  setup %{conn: conn} do
    organization = organization_fixture()
    admin_user = user_fixture(organization: organization, role: "admin")

    # Create test SCIM clients
    scim_client1 =
      scim_client_fixture(
        organization: organization,
        name: "Slack SCIM",
        base_url: "https://api.slack.com/scim/v2"
      )

    scim_client2 =
      scim_client_fixture(
        organization: organization,
        name: "GitHub SCIM",
        base_url: "https://api.github.com/scim/v2",
        is_active: false
      )

    # Set up API headers and authentication as admin
    conn =
      conn
      |> put_req_header("accept", "application/vnd.authify.v1+json")
      |> put_req_header("content-type", "application/vnd.authify.v1+json")
      |> log_in_user(admin_user)
      |> assign(:current_user, admin_user)
      |> assign(:current_organization, organization)
      |> assign(:api_authenticated, true)
      |> assign(:current_scopes, ["scim_clients:read", "scim_clients:write"])

    %{
      conn: conn,
      admin_user: admin_user,
      organization: organization,
      scim_client1: scim_client1,
      scim_client2: scim_client2
    }
  end

  describe "GET /api/scim-clients" do
    test "returns paginated list of SCIM clients with HATEOAS", %{
      conn: conn,
      organization: organization
    } do
      conn = get(conn, "/#{organization.slug}/api/scim-clients")

      assert %{
               "data" => scim_clients,
               "links" => %{
                 "self" => _self_link,
                 "first" => _first_link
               },
               "meta" => %{
                 "total" => 2,
                 "page" => 1,
                 "per_page" => 25
               }
             } = json_response(conn, 200)

      assert length(scim_clients) == 2

      # Check SCIM client structure
      scim_data = List.first(scim_clients)

      assert %{
               "id" => _,
               "type" => "scim_client",
               "attributes" => attributes,
               "links" => %{"self" => _self_link}
             } = scim_data

      # Verify auth_credential is excluded
      refute Map.has_key?(attributes, "auth_credential")

      # Verify expected attributes are present
      assert Map.has_key?(attributes, "name")
      assert Map.has_key?(attributes, "base_url")
      assert Map.has_key?(attributes, "auth_type")
      assert Map.has_key?(attributes, "is_active")
    end

    test "supports pagination parameters", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/api/scim-clients?page=1&per_page=1")

      assert %{
               "data" => scim_clients,
               "meta" => %{
                 "total" => 2,
                 "page" => 1,
                 "per_page" => 1
               }
             } = json_response(conn, 200)

      assert length(scim_clients) == 1
    end

    test "requires appropriate Management API scopes", %{conn: conn, organization: organization} do
      # Set up connection without SCIM client scopes
      conn = assign(conn, :current_scopes, ["profile:read"])

      conn = get(conn, "/#{organization.slug}/api/scim-clients")

      assert %{
               "error" => %{
                 "type" => "insufficient_scope",
                 "message" => _
               }
             } = json_response(conn, 403)
    end

    test "write scope grants read access", %{conn: conn, organization: organization} do
      # Set up connection with only write scope
      conn = assign(conn, :current_scopes, ["scim_clients:write"])

      conn = get(conn, "/#{organization.slug}/api/scim-clients")

      assert %{"data" => _scim_clients} = json_response(conn, 200)
    end
  end

  describe "GET /api/scim-clients/:id" do
    test "returns SCIM client details", %{
      conn: conn,
      scim_client1: scim_client,
      organization: organization
    } do
      conn = get(conn, "/#{organization.slug}/api/scim-clients/#{scim_client.id}")

      assert %{
               "data" => %{
                 "id" => id,
                 "type" => "scim_client",
                 "attributes" => attributes,
                 "links" => %{"self" => _self_link}
               }
             } = json_response(conn, 200)

      assert id == to_string(scim_client.id)
      assert attributes["name"] == scim_client.name
      assert attributes["base_url"] == scim_client.base_url
      refute Map.has_key?(attributes, "auth_credential")
    end

    test "returns 404 for non-existent SCIM client", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/api/scim-clients/99999")

      assert %{
               "error" => %{
                 "type" => "resource_not_found",
                 "message" => "SCIM client not found in organization"
               }
             } = json_response(conn, 404)
    end

    test "requires read or write scope", %{
      conn: conn,
      scim_client1: scim_client,
      organization: organization
    } do
      conn = assign(conn, :current_scopes, ["users:read"])

      conn = get(conn, "/#{organization.slug}/api/scim-clients/#{scim_client.id}")

      assert %{"error" => %{"type" => "insufficient_scope"}} = json_response(conn, 403)
    end
  end

  describe "POST /api/scim-clients" do
    test "creates a new SCIM client with valid data", %{conn: conn, organization: organization} do
      scim_client_params = %{
        "name" => "Example SCIM",
        "description" => "Example provisioning",
        "base_url" => "https://dev-123.okta.com/scim/v2",
        "auth_type" => "bearer",
        "auth_credential" => "test-bearer-token-xyz",
        "sync_users" => true,
        "sync_groups" => true,
        "is_active" => false
      }

      conn =
        post(conn, "/#{organization.slug}/api/scim-clients", scim_client: scim_client_params)

      assert %{
               "data" => %{
                 "id" => id,
                 "type" => "scim_client",
                 "attributes" => attributes
               }
             } = json_response(conn, 201)

      assert attributes["name"] == "Example SCIM"
      assert attributes["base_url"] == "https://dev-123.okta.com/scim/v2"
      assert attributes["auth_type"] == "bearer"
      assert attributes["is_active"] == false
      refute Map.has_key?(attributes, "auth_credential")

      # Verify it was created in the database
      assert Authify.SCIMClient.Client.get_scim_client!(id, organization.id)
    end

    test "returns validation errors for invalid data", %{conn: conn, organization: organization} do
      scim_client_params = %{
        "name" => "",
        "base_url" => "not-a-url"
      }

      conn =
        post(conn, "/#{organization.slug}/api/scim-clients", scim_client: scim_client_params)

      assert %{
               "error" => %{
                 "type" => "validation_failed",
                 "message" => _,
                 "details" => details
               }
             } = json_response(conn, 422)

      assert is_map(details)
    end

    test "requires write scope", %{conn: conn, organization: organization} do
      conn = assign(conn, :current_scopes, ["scim_clients:read"])

      scim_client_params = %{
        "name" => "Test SCIM",
        "base_url" => "https://example.com/scim/v2",
        "auth_type" => "bearer",
        "auth_credential" => "token"
      }

      conn =
        post(conn, "/#{organization.slug}/api/scim-clients", scim_client: scim_client_params)

      assert %{"error" => %{"type" => "insufficient_scope"}} = json_response(conn, 403)
    end

    test "logs audit event for SCIM client creation", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      scim_client_params = %{
        "name" => "Audit Test SCIM",
        "base_url" => "https://audit.example.com/scim/v2",
        "auth_type" => "bearer",
        "auth_credential" => "test-token"
      }

      post(conn, "/#{organization.slug}/api/scim-clients", scim_client: scim_client_params)

      # Give async task time to complete
      Process.sleep(100)

      events =
        Authify.AuditLog.list_events(
          organization_id: organization.id,
          event_type: "scim_client_created"
        )

      refute Enum.empty?(events)
      event = hd(events)
      assert event.actor_id == admin_user.id
      assert event.resource_type == "scim_client"
      assert event.outcome == "success"
    end
  end

  describe "PUT /api/scim-clients/:id" do
    test "updates SCIM client with valid data", %{
      conn: conn,
      scim_client1: scim_client,
      organization: organization
    } do
      update_params = %{
        "name" => "Updated SCIM Client",
        "description" => "Updated description",
        "is_active" => true
      }

      conn =
        put(conn, "/#{organization.slug}/api/scim-clients/#{scim_client.id}",
          scim_client: update_params
        )

      assert %{
               "data" => %{
                 "attributes" => attributes
               }
             } = json_response(conn, 200)

      assert attributes["name"] == "Updated SCIM Client"
      assert attributes["description"] == "Updated description"
      assert attributes["is_active"] == true
    end

    test "allows updating without changing credential", %{
      conn: conn,
      scim_client1: scim_client,
      organization: organization
    } do
      original_credential = scim_client.auth_credential

      update_params = %{
        "name" => "Updated Name",
        "auth_credential" => ""
      }

      conn =
        put(conn, "/#{organization.slug}/api/scim-clients/#{scim_client.id}",
          scim_client: update_params
        )

      assert json_response(conn, 200)

      # Verify credential wasn't cleared
      updated_client =
        Authify.SCIMClient.Client.get_scim_client!(scim_client.id, organization.id)

      assert updated_client.auth_credential == original_credential
    end

    test "returns 404 for non-existent SCIM client", %{conn: conn, organization: organization} do
      update_params = %{"name" => "Updated"}

      conn =
        put(conn, "/#{organization.slug}/api/scim-clients/99999", scim_client: update_params)

      assert %{"error" => %{"type" => "resource_not_found"}} = json_response(conn, 404)
    end

    test "requires write scope", %{
      conn: conn,
      scim_client1: scim_client,
      organization: organization
    } do
      conn = assign(conn, :current_scopes, ["scim_clients:read"])

      update_params = %{"name" => "Updated"}

      conn =
        put(conn, "/#{organization.slug}/api/scim-clients/#{scim_client.id}",
          scim_client: update_params
        )

      assert %{"error" => %{"type" => "insufficient_scope"}} = json_response(conn, 403)
    end
  end

  describe "DELETE /api/scim-clients/:id" do
    test "deletes SCIM client", %{
      conn: conn,
      scim_client1: scim_client,
      organization: organization
    } do
      conn = delete(conn, "/#{organization.slug}/api/scim-clients/#{scim_client.id}")

      assert response(conn, 204)

      # Verify it was deleted
      assert_raise Ecto.NoResultsError, fn ->
        Authify.SCIMClient.Client.get_scim_client!(scim_client.id, organization.id)
      end
    end

    test "returns 404 for non-existent SCIM client", %{conn: conn, organization: organization} do
      conn = delete(conn, "/#{organization.slug}/api/scim-clients/99999")

      assert %{"error" => %{"type" => "resource_not_found"}} = json_response(conn, 404)
    end

    test "requires write scope", %{
      conn: conn,
      scim_client1: scim_client,
      organization: organization
    } do
      conn = assign(conn, :current_scopes, ["scim_clients:read"])

      conn = delete(conn, "/#{organization.slug}/api/scim-clients/#{scim_client.id}")

      assert %{"error" => %{"type" => "insufficient_scope"}} = json_response(conn, 403)
    end

    test "logs audit event for deletion", %{
      conn: conn,
      scim_client1: scim_client,
      organization: organization,
      admin_user: admin_user
    } do
      delete(conn, "/#{organization.slug}/api/scim-clients/#{scim_client.id}")

      # Give async task time to complete
      Process.sleep(100)

      events =
        Authify.AuditLog.list_events(
          organization_id: organization.id,
          event_type: "scim_client_deleted"
        )

      refute Enum.empty?(events)
      event = hd(events)
      assert event.actor_id == admin_user.id
      assert event.resource_id == scim_client.id
      assert event.outcome == "success"
    end
  end

  describe "POST /api/scim-clients/:id/sync" do
    test "triggers manual sync for SCIM client", %{
      conn: conn,
      scim_client1: scim_client,
      organization: organization
    } do
      conn = post(conn, "/#{organization.slug}/api/scim-clients/#{scim_client.id}/sync")

      assert %{
               "status" => "sync_triggered",
               "message" => "Full sync initiated for SCIM client"
             } = json_response(conn, 200)
    end

    test "returns 404 for non-existent SCIM client", %{conn: conn, organization: organization} do
      conn = post(conn, "/#{organization.slug}/api/scim-clients/99999/sync")

      assert %{"error" => %{"type" => "resource_not_found"}} = json_response(conn, 404)
    end

    test "requires write scope", %{
      conn: conn,
      scim_client1: scim_client,
      organization: organization
    } do
      conn = assign(conn, :current_scopes, ["scim_clients:read"])

      conn = post(conn, "/#{organization.slug}/api/scim-clients/#{scim_client.id}/sync")

      assert %{"error" => %{"type" => "insufficient_scope"}} = json_response(conn, 403)
    end
  end

  describe "GET /api/scim-clients/:id/logs" do
    test "returns sync logs for SCIM client", %{
      conn: conn,
      scim_client1: scim_client,
      organization: organization
    } do
      # Create some sync logs
      Authify.SCIMClient.Client.create_sync_log(%{
        scim_client_id: scim_client.id,
        resource_type: "User",
        resource_id: 1,
        operation: "create",
        status: "success",
        http_status: 201
      })

      conn = get(conn, "/#{organization.slug}/api/scim-clients/#{scim_client.id}/logs")

      assert %{
               "data" => logs,
               "meta" => %{
                 "total" => total,
                 "page" => 1,
                 "per_page" => 50
               }
             } = json_response(conn, 200)

      assert total >= 1
      assert is_list(logs)
    end

    test "supports pagination", %{
      conn: conn,
      scim_client1: scim_client,
      organization: organization
    } do
      conn =
        get(
          conn,
          "/#{organization.slug}/api/scim-clients/#{scim_client.id}/logs?page=1&per_page=10"
        )

      assert %{
               "meta" => %{
                 "page" => 1,
                 "per_page" => 10
               }
             } = json_response(conn, 200)
    end

    test "returns 404 for non-existent SCIM client", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/api/scim-clients/99999/logs")

      assert %{"error" => %{"type" => "resource_not_found"}} = json_response(conn, 404)
    end

    test "requires read or write scope", %{
      conn: conn,
      scim_client1: scim_client,
      organization: organization
    } do
      conn = assign(conn, :current_scopes, ["users:read"])

      conn = get(conn, "/#{organization.slug}/api/scim-clients/#{scim_client.id}/logs")

      assert %{"error" => %{"type" => "insufficient_scope"}} = json_response(conn, 403)
    end
  end

  describe "multi-tenant isolation" do
    test "cannot access SCIM clients from another organization", %{
      conn: conn,
      organization: organization
    } do
      other_org = organization_fixture(name: "Other Org", slug: "other-org")
      scim_client = scim_client_fixture(organization: other_org)

      # Try to access from current org's context (should fail)
      conn = get(conn, "/#{organization.slug}/api/scim-clients/#{scim_client.id}")

      assert %{"error" => %{"type" => "resource_not_found"}} = json_response(conn, 404)
    end

    test "SCIM clients are filtered by organization in index", %{
      conn: conn,
      organization: organization
    } do
      # Create client for other org
      other_org = organization_fixture(name: "Other Org", slug: "other-org")
      _other_client = scim_client_fixture(organization: other_org, name: "Other Client")

      conn = get(conn, "/#{organization.slug}/api/scim-clients")
      response = json_response(conn, 200)

      # Should only see clients from current org (2 from setup)
      assert response["meta"]["total"] == 2
      client_names = Enum.map(response["data"], & &1["attributes"]["name"])
      refute "Other Client" in client_names
    end
  end
end
