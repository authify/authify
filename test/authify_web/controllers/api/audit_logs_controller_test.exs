defmodule AuthifyWeb.API.AuditLogsControllerTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  alias Authify.Accounts.User
  alias Authify.AuditLog

  setup %{conn: conn} do
    organization = organization_fixture()
    admin_user = user_fixture(organization: organization, role: "admin")

    # Create some audit log events for testing
    {:ok, event1} =
      AuditLog.log_event(:login_success, %{
        organization_id: organization.id,
        actor_type: "user",
        actor_id: admin_user.id,
        actor_name: User.get_primary_email_value(admin_user),
        outcome: "success",
        ip_address: "192.168.1.1",
        user_agent: "Test Browser 1.0"
      })

    {:ok, event2} =
      AuditLog.log_event(:oauth_token_granted, %{
        organization_id: organization.id,
        actor_type: "application",
        actor_id: 1,
        actor_name: "Test App",
        outcome: "success",
        resource_type: "oauth_token",
        resource_id: 1,
        metadata: %{"scopes" => "users:read"}
      })

    {:ok, event3} =
      AuditLog.log_event(:login_failure, %{
        organization_id: organization.id,
        actor_type: "user",
        outcome: "failure",
        ip_address: "192.168.1.2"
      })

    # Set up API headers and authentication as admin with audit_logs:read scope
    conn =
      conn
      |> put_req_header("accept", "application/vnd.authify.v1+json")
      |> put_req_header("content-type", "application/vnd.authify.v1+json")
      |> log_in_user(admin_user)
      |> assign(:current_user, admin_user)
      |> assign(:current_organization, organization)
      |> assign(:api_authenticated, true)
      |> assign(:current_scopes, ["audit_logs:read"])

    %{
      conn: conn,
      admin_user: admin_user,
      organization: organization,
      event1: event1,
      event2: event2,
      event3: event3
    }
  end

  describe "GET /api/audit-logs" do
    test "returns paginated list of audit logs with HATEOAS", %{
      conn: conn,
      organization: organization
    } do
      conn = get(conn, "/#{organization.slug}/api/audit-logs")

      assert %{
               "data" => events,
               "links" => %{
                 "self" => self_link,
                 "first" => first_link
               },
               "meta" => %{
                 "total" => 3,
                 "page" => 1,
                 "per_page" => 25
               }
             } = json_response(conn, 200)

      assert self_link == "http://localhost:4002/#{organization.slug}/api/audit-logs"
      assert length(events) == 3
      assert String.contains?(first_link, "page=1&per_page=25")

      # Check audit log structure
      event_data = List.first(events)

      assert %{
               "id" => _,
               "type" => "audit_log",
               "attributes" => attributes,
               "links" => %{"self" => self_link}
             } = event_data

      assert String.starts_with?(self_link, "/#{organization.slug}/api/audit-logs/")
      assert Map.has_key?(attributes, "event_type")
      assert Map.has_key?(attributes, "actor_type")
      assert Map.has_key?(attributes, "outcome")
      assert Map.has_key?(attributes, "inserted_at")
    end

    test "supports pagination parameters", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/api/audit-logs?page=1&per_page=2")

      assert %{
               "data" => events,
               "meta" => %{
                 "total" => 3,
                 "page" => 1,
                 "per_page" => 2
               }
             } = json_response(conn, 200)

      assert length(events) == 2
    end

    test "supports filtering by event_type", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/api/audit-logs?event_type=login_success")

      assert %{
               "data" => events,
               "meta" => %{
                 "total" => 1
               }
             } = json_response(conn, 200)

      assert length(events) == 1
      assert List.first(events)["attributes"]["event_type"] == "login_success"
    end

    test "supports filtering by actor_type", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/api/audit-logs?actor_type=application")

      assert %{
               "data" => events,
               "meta" => %{
                 "total" => 1
               }
             } = json_response(conn, 200)

      assert length(events) == 1
      assert List.first(events)["attributes"]["actor_type"] == "application"
    end

    test "supports filtering by outcome", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/api/audit-logs?outcome=failure")

      assert %{
               "data" => events,
               "meta" => %{
                 "total" => 1
               }
             } = json_response(conn, 200)

      assert length(events) == 1
      assert List.first(events)["attributes"]["outcome"] == "failure"
    end

    test "supports filtering by resource_type", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/api/audit-logs?resource_type=oauth_token")

      assert %{
               "data" => events,
               "meta" => %{
                 "total" => 1
               }
             } = json_response(conn, 200)

      assert length(events) == 1
      assert List.first(events)["attributes"]["resource_type"] == "oauth_token"
    end

    test "requires audit_logs:read scope", %{conn: conn, organization: organization} do
      # Set up connection without audit_logs:read scope
      conn =
        conn
        |> assign(:current_scopes, ["users:read"])

      conn = get(conn, "/#{organization.slug}/api/audit-logs")

      assert %{
               "error" => %{
                 "type" => "insufficient_scope",
                 "message" => "Insufficient scope to access this resource"
               }
             } = json_response(conn, 403)
    end

    test "does not return audit logs from other organizations", %{conn: conn} do
      other_org = organization_fixture()

      # Create an audit log in a different organization
      {:ok, _other_event} =
        AuditLog.log_event(:login_success, %{
          organization_id: other_org.id,
          actor_type: "user",
          outcome: "success"
        })

      # Should only see events from current organization
      conn = get(conn, "/#{conn.assigns.current_organization.slug}/api/audit-logs")

      assert %{
               "data" => _events,
               "meta" => %{
                 "total" => 3
               }
             } = json_response(conn, 200)
    end
  end

  describe "GET /api/audit-logs/:id" do
    test "returns audit log details", %{
      conn: conn,
      organization: organization,
      event1: event1
    } do
      conn = get(conn, "/#{organization.slug}/api/audit-logs/#{event1.id}")

      assert %{
               "data" => %{
                 "id" => id,
                 "type" => "audit_log",
                 "attributes" => attributes,
                 "links" => %{"self" => self_link}
               },
               "links" => %{"self" => _self_link}
             } = json_response(conn, 200)

      assert id == to_string(event1.id)
      assert attributes["event_type"] == "login_success"
      assert attributes["actor_type"] == "user"
      assert attributes["outcome"] == "success"
      assert String.ends_with?(self_link, "/api/audit-logs/#{event1.id}")
    end

    test "returns 404 for non-existent audit log", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/api/audit-logs/99999")

      assert %{
               "error" => %{
                 "type" => "resource_not_found",
                 "message" => "Audit log entry not found in organization"
               }
             } = json_response(conn, 404)
    end

    test "returns 404 for audit log from different organization", %{
      conn: conn,
      organization: organization
    } do
      other_org = organization_fixture()

      {:ok, other_event} =
        AuditLog.log_event(:login_success, %{
          organization_id: other_org.id,
          actor_type: "user",
          outcome: "success"
        })

      conn = get(conn, "/#{organization.slug}/api/audit-logs/#{other_event.id}")

      assert %{
               "error" => %{
                 "type" => "resource_not_found",
                 "message" => "Audit log entry not found in organization"
               }
             } = json_response(conn, 404)
    end

    test "requires audit_logs:read scope", %{
      conn: conn,
      organization: organization,
      event1: event1
    } do
      # Set up connection without audit_logs:read scope
      conn =
        conn
        |> assign(:current_scopes, ["users:read"])

      conn = get(conn, "/#{organization.slug}/api/audit-logs/#{event1.id}")

      assert %{
               "error" => %{
                 "type" => "insufficient_scope",
                 "message" => "Insufficient scope to access this resource"
               }
             } = json_response(conn, 403)
    end
  end
end
