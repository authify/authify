defmodule AuthifyWeb.OrganizationsControllerTest do
  # async: false — the delete action issues multiple cascading DB queries
  # that exhaust the connection pool under concurrent load
  use AuthifyWeb.ConnCase, async: false

  import Authify.AccountsFixtures

  setup %{conn: conn} do
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
      ref = :telemetry_test.attach_event_handlers(self(), [[:authify, :audit_log, :event]])
      admin_id = global_admin.id

      create_attrs = %{
        name: "Audit Test Org",
        slug: "audit-test-org-#{System.unique_integer([:positive])}"
      }

      post(conn, ~p"/#{global_org.slug}/organizations", organization: create_attrs)

      assert_receive {[:authify, :audit_log, :event], ^ref, _,
                      %{event_type: "organization_created", actor_id: ^admin_id} = metadata}

      assert metadata.actor_type == "user"
      assert metadata.resource_type == "organization"
      assert metadata.outcome == "success"

      :telemetry.detach(ref)
    end

    test "logs organization updates", %{
      conn: conn,
      global_admin: global_admin,
      global_org: global_org
    } do
      ref = :telemetry_test.attach_event_handlers(self(), [[:authify, :audit_log, :event]])
      admin_id = global_admin.id

      test_org = organization_fixture()
      org_id = test_org.id

      put(conn, ~p"/#{global_org.slug}/organizations/#{test_org.id}",
        organization: %{name: "Updated Org Name"}
      )

      assert_receive {[:authify, :audit_log, :event], ^ref, _,
                      %{
                        event_type: "organization_updated",
                        actor_id: ^admin_id,
                        resource_id: ^org_id
                      } = metadata}

      assert metadata.actor_type == "user"
      assert metadata.resource_type == "organization"
      assert metadata.outcome == "success"

      :telemetry.detach(ref)
    end

    test "logs organization deletion", %{
      conn: conn,
      global_admin: global_admin,
      global_org: global_org
    } do
      ref = :telemetry_test.attach_event_handlers(self(), [[:authify, :audit_log, :event]])
      admin_id = global_admin.id

      test_org = organization_fixture()
      org_id = test_org.id

      delete(conn, ~p"/#{global_org.slug}/organizations/#{test_org.id}")

      assert_receive {[:authify, :audit_log, :event], ^ref, _,
                      %{
                        event_type: "organization_deleted",
                        actor_id: ^admin_id,
                        resource_id: ^org_id
                      } = metadata}

      assert metadata.actor_type == "user"
      assert metadata.resource_type == "organization"
      assert metadata.outcome == "success"

      :telemetry.detach(ref)
    end
  end
end
