defmodule AuthifyWeb.OrganizationsControllerTest do
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures

  setup %{conn: conn} do
    # Use the existing global organization
    global_org = Authify.Accounts.get_organization_by_slug("authify-global")
    global_admin = user_fixture(organization: global_org, role: "admin")

    conn =
      conn
      |> log_in_user(global_admin)
      |> assign(:current_user, global_admin)
      |> assign(:current_organization, global_org)

    %{conn: conn, global_admin: global_admin, global_org: global_org}
  end

  describe "audit logging" do
    test "logs organization creation", %{
      conn: conn,
      global_admin: global_admin,
      global_org: global_org
    } do
      create_attrs = %{
        name: "Audit Test Org",
        slug: "audit-test-org"
      }

      post(conn, ~p"/#{global_org.slug}/organizations", organization: create_attrs)

      # Give async task time to complete
      Process.sleep(100)

      events =
        Authify.AuditLog.list_events(
          organization_id: global_org.id,
          event_type: "organization_created"
        )

      assert length(events) == 1

      event = hd(events)
      assert event.actor_type == "user"
      assert event.actor_id == global_admin.id
      assert event.resource_type == "organization"
      assert event.outcome == "success"
      assert event.metadata["organization_name"] == "Audit Test Org"
      assert event.metadata["slug"] == "audit-test-org"
    end

    test "logs organization updates", %{
      conn: conn,
      global_admin: global_admin,
      global_org: global_org
    } do
      test_org = organization_fixture()
      update_attrs = %{name: "Updated Org Name"}

      put(conn, ~p"/#{global_org.slug}/organizations/#{test_org.id}", organization: update_attrs)

      # Give async task time to complete
      Process.sleep(100)

      events =
        Authify.AuditLog.list_events(
          organization_id: global_org.id,
          event_type: "organization_updated"
        )

      assert length(events) == 1

      event = hd(events)
      assert event.actor_type == "user"
      assert event.actor_id == global_admin.id
      assert event.resource_type == "organization"
      assert event.resource_id == test_org.id
      assert event.outcome == "success"
    end

    test "logs organization deletion", %{
      conn: conn,
      global_admin: global_admin,
      global_org: global_org
    } do
      test_org = organization_fixture()

      delete(conn, ~p"/#{global_org.slug}/organizations/#{test_org.id}")

      # Give async task time to complete
      Process.sleep(100)

      events =
        Authify.AuditLog.list_events(
          organization_id: global_org.id,
          event_type: "organization_deleted"
        )

      assert length(events) == 1

      event = hd(events)
      assert event.actor_type == "user"
      assert event.actor_id == global_admin.id
      assert event.resource_type == "organization"
      assert event.resource_id == test_org.id
      assert event.outcome == "success"
      assert event.metadata["slug"] == test_org.slug
    end
  end
end
