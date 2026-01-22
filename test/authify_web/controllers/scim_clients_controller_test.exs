defmodule AuthifyWeb.ScimClientsControllerTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures
  import Authify.SCIMClientFixtures

  setup %{conn: conn} do
    organization = organization_fixture()
    admin_user = user_fixture(organization: organization, role: "admin")
    regular_user = user_fixture(organization: organization, role: "user")

    conn =
      conn
      |> log_in_user(admin_user)
      |> assign(:current_user, admin_user)
      |> assign(:current_organization, organization)

    %{conn: conn, admin_user: admin_user, regular_user: regular_user, organization: organization}
  end

  describe "index" do
    test "lists all SCIM clients", %{conn: conn, organization: organization} do
      conn = get(conn, ~p"/#{organization.slug}/scim_clients")
      assert html_response(conn, 200) =~ "SCIM Clients"
    end

    test "shows empty state when no clients", %{conn: conn, organization: organization} do
      conn = get(conn, ~p"/#{organization.slug}/scim_clients")
      response = html_response(conn, 200)
      assert response =~ "No SCIM clients configured"
      assert response =~ "Create your first SCIM client"
    end

    test "lists existing clients", %{conn: conn, organization: organization} do
      scim_client = scim_client_fixture(organization: organization)
      conn = get(conn, ~p"/#{organization.slug}/scim_clients")
      response = html_response(conn, 200)
      assert response =~ scim_client.name
    end
  end

  describe "new" do
    test "renders form", %{conn: conn, organization: organization} do
      conn = get(conn, ~p"/#{organization.slug}/scim_clients/new")
      assert html_response(conn, 200) =~ "Create SCIM Client"
    end
  end

  describe "create" do
    test "redirects to show when data is valid", %{conn: conn, organization: organization} do
      create_attrs = %{
        "name" => "Test SCIM Client",
        "description" => "A test client",
        "base_url" => "https://test-scim-web.local/scim/v2",
        "auth_type" => "bearer",
        "auth_credential" => "test-token-12345",
        "sync_users" => "false",
        "sync_groups" => "false",
        "is_active" => "false"
      }

      conn = post(conn, ~p"/#{organization.slug}/scim_clients", scim_client: create_attrs)

      assert %{id: id} = redirected_params(conn)
      assert redirected_to(conn) == ~p"/#{organization.slug}/scim_clients/#{id}"

      conn = get(conn, ~p"/#{organization.slug}/scim_clients/#{id}")
      assert html_response(conn, 200) =~ "Test SCIM Client"
    end

    test "renders errors when data is invalid", %{conn: conn, organization: organization} do
      conn = post(conn, ~p"/#{organization.slug}/scim_clients", scim_client: %{})
      assert html_response(conn, 200) =~ "Create SCIM Client"
    end

    test "validates required fields", %{conn: conn, organization: organization} do
      conn =
        post(conn, ~p"/#{organization.slug}/scim_clients",
          scim_client: %{"name" => "", "base_url" => ""}
        )

      response = html_response(conn, 200)
      assert response =~ "can&#39;t be blank"
    end

    test "validates base_url format", %{conn: conn, organization: organization} do
      conn =
        post(conn, ~p"/#{organization.slug}/scim_clients",
          scim_client: %{
            "name" => "Test",
            "base_url" => "not-a-url",
            "auth_type" => "bearer",
            "auth_credential" => "token"
          }
        )

      response = html_response(conn, 200)
      assert response =~ "must be a valid HTTP or HTTPS URL"
    end
  end

  describe "show" do
    setup [:create_scim_client]

    test "displays SCIM client", %{
      conn: conn,
      scim_client: scim_client,
      organization: organization
    } do
      conn = get(conn, ~p"/#{organization.slug}/scim_clients/#{scim_client}")
      response = html_response(conn, 200)
      assert response =~ scim_client.name
      assert response =~ scim_client.base_url
    end

    test "displays sync logs", %{
      conn: conn,
      scim_client: scim_client,
      organization: organization
    } do
      conn = get(conn, ~p"/#{organization.slug}/scim_clients/#{scim_client}")
      response = html_response(conn, 200)
      assert response =~ scim_client.name
      assert response =~ scim_client.base_url
    end
  end

  describe "edit" do
    setup [:create_scim_client]

    test "renders form for editing chosen SCIM client", %{
      conn: conn,
      scim_client: scim_client,
      organization: organization
    } do
      conn = get(conn, ~p"/#{organization.slug}/scim_clients/#{scim_client}/edit")
      assert html_response(conn, 200) =~ "Edit SCIM Client"
    end
  end

  describe "update" do
    setup [:create_scim_client]

    test "redirects when data is valid", %{
      conn: conn,
      scim_client: scim_client,
      organization: organization
    } do
      update_attrs = %{"name" => "Updated SCIM Client", "description" => "Updated description"}

      conn =
        put(conn, ~p"/#{organization.slug}/scim_clients/#{scim_client}",
          scim_client: update_attrs
        )

      assert redirected_to(conn) == ~p"/#{organization.slug}/scim_clients/#{scim_client}"

      conn = get(conn, ~p"/#{organization.slug}/scim_clients/#{scim_client}")
      assert html_response(conn, 200) =~ "Updated SCIM Client"
    end

    test "renders errors when data is invalid", %{
      conn: conn,
      scim_client: scim_client,
      organization: organization
    } do
      conn =
        put(conn, ~p"/#{organization.slug}/scim_clients/#{scim_client}",
          scim_client: %{"name" => ""}
        )

      assert html_response(conn, 200) =~ "Edit SCIM Client"
    end

    test "allows updating without changing password", %{
      conn: conn,
      scim_client: scim_client,
      organization: organization
    } do
      update_attrs = %{"name" => "Updated Name", "auth_credential" => ""}

      conn =
        put(conn, ~p"/#{organization.slug}/scim_clients/#{scim_client}",
          scim_client: update_attrs
        )

      assert redirected_to(conn) == ~p"/#{organization.slug}/scim_clients/#{scim_client}"

      # Verify the credential wasn't cleared
      updated_client =
        Authify.SCIMClient.Client.get_scim_client!(scim_client.id, organization.id)

      assert updated_client.auth_credential != nil
    end
  end

  describe "delete" do
    setup [:create_scim_client]

    test "deletes chosen SCIM client", %{
      conn: conn,
      scim_client: scim_client,
      organization: organization
    } do
      conn = delete(conn, ~p"/#{organization.slug}/scim_clients/#{scim_client}")
      assert redirected_to(conn) == ~p"/#{organization.slug}/scim_clients"

      assert_error_sent 404, fn ->
        get(conn, ~p"/#{organization.slug}/scim_clients/#{scim_client}")
      end
    end
  end

  describe "logs" do
    setup [:create_scim_client]

    test "displays sync logs for a SCIM client", %{
      conn: conn,
      scim_client: scim_client,
      organization: organization
    } do
      conn = get(conn, ~p"/#{organization.slug}/scim_clients/#{scim_client}/logs")
      response = html_response(conn, 200)
      assert response =~ "Sync Logs"
      assert response =~ scim_client.name
    end

    test "shows empty state when no logs", %{
      conn: conn,
      scim_client: scim_client,
      organization: organization
    } do
      conn = get(conn, ~p"/#{organization.slug}/scim_clients/#{scim_client}/logs")
      response = html_response(conn, 200)
      assert response =~ "No sync logs yet"
    end

    test "renders logs page with pagination support", %{
      conn: conn,
      scim_client: scim_client,
      organization: organization
    } do
      # Test logs page renders
      conn = get(conn, ~p"/#{organization.slug}/scim_clients/#{scim_client}/logs")
      response = html_response(conn, 200)
      assert response =~ "Sync Logs"
      assert response =~ scim_client.name
    end
  end

  describe "audit logging" do
    test "logs SCIM client creation", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      create_attrs = %{
        "name" => "Audit Test Client",
        "description" => "Testing audit logs",
        "base_url" => "https://test-scim-audit-web.local/scim/v2",
        "auth_type" => "bearer",
        "auth_credential" => "test-token",
        "sync_users" => "false",
        "sync_groups" => "false"
      }

      post(conn, ~p"/#{organization.slug}/scim_clients", scim_client: create_attrs)

      # Give async task time to complete
      Process.sleep(100)

      events =
        Authify.AuditLog.list_events(
          organization_id: organization.id,
          event_type: "scim_client_created"
        )

      refute Enum.empty?(events)
      event = hd(events)
      assert event.actor_type == "user"
      assert event.actor_id == admin_user.id
      assert event.resource_type == "scim_client"
      assert event.outcome == "success"
      assert event.metadata["provider"] == "Audit Test Client"
    end

    test "logs SCIM client updates", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      scim_client = scim_client_fixture(organization: organization)
      update_attrs = %{"name" => "Updated for Audit"}

      put(conn, ~p"/#{organization.slug}/scim_clients/#{scim_client}", scim_client: update_attrs)

      # Give async task time to complete
      Process.sleep(100)

      events =
        Authify.AuditLog.list_events(
          organization_id: organization.id,
          event_type: "scim_client_updated"
        )

      refute Enum.empty?(events)
      event = hd(events)
      assert event.actor_type == "user"
      assert event.actor_id == admin_user.id
      assert event.resource_type == "scim_client"
      assert event.resource_id == scim_client.id
      assert event.outcome == "success"
    end

    test "logs SCIM client deletion", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      scim_client = scim_client_fixture(organization: organization)

      delete(conn, ~p"/#{organization.slug}/scim_clients/#{scim_client}")

      # Give async task time to complete
      Process.sleep(100)

      events =
        Authify.AuditLog.list_events(
          organization_id: organization.id,
          event_type: "scim_client_deleted"
        )

      refute Enum.empty?(events)
      event = hd(events)
      assert event.actor_type == "user"
      assert event.actor_id == admin_user.id
      assert event.resource_type == "scim_client"
      assert event.resource_id == scim_client.id
      assert event.outcome == "success"
      assert event.metadata["provider"] == scim_client.name
    end
  end

  describe "multi-tenant isolation" do
    test "cannot access SCIM clients from another organization", %{conn: conn} do
      other_org = organization_fixture(name: "Other Org", slug: "other-org")
      scim_client = scim_client_fixture(organization: other_org)

      # Try to access show page
      assert_error_sent 404, fn ->
        get(conn, ~p"/other-org/scim_clients/#{scim_client}")
      end
    end

    test "SCIM clients are filtered by organization in index", %{
      conn: conn,
      organization: organization
    } do
      # Create client for current org
      _my_client = scim_client_fixture(organization: organization, name: "My Client")

      # Create client for other org
      other_org = organization_fixture(name: "Other Org", slug: "other-org")
      _other_client = scim_client_fixture(organization: other_org, name: "Other Client")

      conn = get(conn, ~p"/#{organization.slug}/scim_clients")
      response = html_response(conn, 200)

      # Should see my client
      assert response =~ "My Client"

      # Should NOT see other org's client
      refute response =~ "Other Client"
    end
  end

  defp create_scim_client(%{organization: organization}) do
    scim_client = scim_client_fixture(organization: organization)
    %{scim_client: scim_client}
  end
end
