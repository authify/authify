defmodule AuthifyWeb.AuditLogsControllerTest do
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures

  alias Authify.AuditLog
  alias Authify.Guardian

  defp sign_in_user(conn, user, organization) do
    conn
    |> Plug.Test.init_test_session(%{})
    |> Guardian.Plug.sign_in(user)
    |> put_session(:current_organization_id, organization.id)
    |> assign(:current_organization, organization)
    |> assign(:current_user, user)
  end

  describe "index" do
    test "requires authentication", %{conn: conn} do
      organization = organization_fixture()
      conn = get(conn, ~p"/#{organization.slug}/audit_logs")
      assert redirected_to(conn) =~ "/login"
    end

    test "requires admin access", %{conn: conn} do
      organization = organization_fixture()
      regular_user = user_for_organization_fixture(organization)
      conn = sign_in_user(conn, regular_user, organization)

      conn = get(conn, ~p"/#{organization.slug}/audit_logs")
      assert redirected_to(conn) =~ "/dashboard"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Admin privileges required"
    end

    test "allows admin to view audit logs", %{conn: conn} do
      organization = organization_fixture()
      admin_user = admin_user_fixture(organization)
      conn = sign_in_user(conn, admin_user, organization)

      # Create some audit events
      AuditLog.log_event(:login_success, %{
        organization_id: organization.id,
        user_id: admin_user.id,
        actor_type: "user",
        actor_name: "Admin User",
        outcome: "success",
        ip_address: "127.0.0.1"
      })

      AuditLog.log_event(:user_created, %{
        organization_id: organization.id,
        user_id: admin_user.id,
        actor_type: "user",
        actor_name: "Admin User",
        outcome: "success",
        ip_address: "127.0.0.1"
      })

      conn = get(conn, ~p"/#{organization.slug}/audit_logs")
      html = html_response(conn, 200)
      assert html =~ "Audit Logs"
      assert html =~ "Login Success"
      assert html =~ "User Created"
    end

    test "filters events by event type", %{conn: conn} do
      organization = organization_fixture()
      admin_user = admin_user_fixture(organization)
      conn = sign_in_user(conn, admin_user, organization)

      # Create different event types
      AuditLog.log_event(:login_success, %{
        organization_id: organization.id,
        user_id: admin_user.id,
        actor_type: "user",
        outcome: "success"
      })

      AuditLog.log_event(:user_created, %{
        organization_id: organization.id,
        user_id: admin_user.id,
        actor_type: "user",
        outcome: "success"
      })

      # Filter by login_success
      conn = get(conn, ~p"/#{organization.slug}/audit_logs?event_type=login_success")
      html = html_response(conn, 200)
      # Check we're showing only 1 event
      assert html =~ "Showing 1 events"
    end

    test "filters events by outcome", %{conn: conn} do
      organization = organization_fixture()
      admin_user = admin_user_fixture(organization)
      conn = sign_in_user(conn, admin_user, organization)

      # Create events with different outcomes
      AuditLog.log_event(:login_success, %{
        organization_id: organization.id,
        user_id: admin_user.id,
        actor_type: "user",
        outcome: "success"
      })

      AuditLog.log_event(:login_failure, %{
        organization_id: organization.id,
        actor_type: "user",
        outcome: "failure"
      })

      # Filter by failure
      conn = get(conn, ~p"/#{organization.slug}/audit_logs?outcome=failure")
      html = html_response(conn, 200)
      assert html =~ "Login Failure"
      # Check we're showing only 1 event
      assert html =~ "Showing 1 events"
    end

    test "filters events by date range", %{conn: conn} do
      organization = organization_fixture()
      admin_user = admin_user_fixture(organization)
      conn = sign_in_user(conn, admin_user, organization)

      # Create an event
      AuditLog.log_event(:login_success, %{
        organization_id: organization.id,
        user_id: admin_user.id,
        actor_type: "user",
        outcome: "success"
      })

      # Filter by today's date
      today = Date.utc_today() |> Date.to_iso8601()

      conn = get(conn, ~p"/#{organization.slug}/audit_logs?date_from=#{today}&date_to=#{today}")
      html = html_response(conn, 200)
      assert html =~ "Login Success"
    end

    test "only shows events for current organization", %{conn: conn} do
      organization = organization_fixture()
      admin_user = admin_user_fixture(organization)
      conn = sign_in_user(conn, admin_user, organization)

      # Create an event for this organization
      AuditLog.log_event(:login_success, %{
        organization_id: organization.id,
        user_id: admin_user.id,
        actor_type: "user",
        outcome: "success"
      })

      # Create another organization and event
      other_org = organization_fixture()

      AuditLog.log_event(:login_success, %{
        organization_id: other_org.id,
        user_id: admin_user.id,
        actor_type: "user",
        outcome: "success",
        metadata: %{marker: "other_org_event"}
      })

      conn = get(conn, ~p"/#{organization.slug}/audit_logs")
      html = html_response(conn, 200)
      # Should not contain the other org's event
      refute html =~ "other_org_event"
    end
  end

  describe "show" do
    test "requires authentication", %{conn: conn} do
      organization = organization_fixture()
      conn = get(conn, ~p"/#{organization.slug}/audit_logs/123")
      assert redirected_to(conn) =~ "/login"
    end

    test "requires admin access", %{conn: conn} do
      organization = organization_fixture()
      regular_user = user_for_organization_fixture(organization)
      conn = sign_in_user(conn, regular_user, organization)

      # Create an audit event
      {:ok, event} =
        AuditLog.log_event(:login_success, %{
          organization_id: organization.id,
          user_id: regular_user.id,
          actor_type: "user",
          outcome: "success"
        })

      conn = get(conn, ~p"/#{organization.slug}/audit_logs/#{event.id}")
      assert redirected_to(conn) =~ "/dashboard"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Admin privileges required"
    end

    test "displays event details for admin", %{conn: conn} do
      organization = organization_fixture()
      admin_user = admin_user_fixture(organization)
      conn = sign_in_user(conn, admin_user, organization)

      # Create an audit event with metadata
      {:ok, event} =
        AuditLog.log_event(:user_created, %{
          organization_id: organization.id,
          user_id: admin_user.id,
          actor_type: "user",
          actor_name: "Admin User",
          outcome: "success",
          ip_address: "192.168.1.1",
          user_agent: "Mozilla/5.0",
          metadata: %{
            created_user_id: 456,
            created_user_email: "newuser@example.com"
          }
        })

      conn = get(conn, ~p"/#{organization.slug}/audit_logs/#{event.id}")
      html = html_response(conn, 200)
      assert html =~ "Audit Event Details"
      assert html =~ "User Created"
      assert html =~ "Admin User"
      assert html =~ "192.168.1.1"
      assert html =~ "Mozilla/5.0"
      assert html =~ "newuser@example.com"
    end

    test "prevents viewing events from other organizations", %{conn: conn} do
      organization = organization_fixture()
      admin_user = admin_user_fixture(organization)
      conn = sign_in_user(conn, admin_user, organization)

      # Create another organization and event
      other_org = organization_fixture()

      {:ok, other_event} =
        AuditLog.log_event(:login_success, %{
          organization_id: other_org.id,
          actor_type: "user",
          outcome: "success"
        })

      # Try to access the other organization's event
      conn = get(conn, ~p"/#{organization.slug}/audit_logs/#{other_event.id}")
      assert html_response(conn, 404)
    end
  end
end
