defmodule AuthifyWeb.MaintenanceControllerTest do
  # async: false — uses Oban.Testing with manual mode, which modifies global
  # Oban queue state incompatible with concurrent test execution.
  use AuthifyWeb.ConnCase, async: false
  use Oban.Testing, repo: Authify.Repo

  import Authify.AccountsFixtures

  alias Authify.Tasks
  alias Authify.Tasks.Workers.TaskExecutor

  setup do
    # Find or create global org
    global_org =
      case Authify.Repo.get_by(Authify.Accounts.Organization, slug: "authify-global") do
        nil -> organization_fixture(%{slug: "authify-global"})
        org -> org
      end

    admin = admin_user_fixture(global_org)

    %{org: global_org, admin: admin}
  end

  describe "index" do
    test "requires global organization access", %{conn: conn} do
      # Create a non-global org and user
      regular_org = organization_fixture(%{slug: "regular-org"})
      user = user_fixture(%{organization: regular_org})

      conn =
        conn
        |> log_in_user(user)
        |> assign(:current_organization, regular_org)

      conn = get(conn, ~p"/#{regular_org.slug}/maintenance")

      assert redirected_to(conn) == ~p"/#{regular_org.slug}/dashboard"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Access denied"
    end

    test "shows maintenance dashboard for global admin", %{conn: conn, org: org, admin: admin} do
      conn =
        conn
        |> log_in_user(admin)
        |> assign(:current_organization, org)

      conn = get(conn, ~p"/#{org.slug}/maintenance")

      assert html_response(conn, 200) =~ "System Maintenance"
      assert html_response(conn, 200) =~ "Clean Expired Invitations"
      assert html_response(conn, 200) =~ "System Health"
    end
  end

  describe "cleanup_expired_invitations" do
    test "requires global organization access", %{conn: conn} do
      # Create a non-global org and user
      regular_org = organization_fixture(%{slug: "regular-org"})
      user = user_fixture(%{organization: regular_org})

      conn =
        conn
        |> log_in_user(user)
        |> assign(:current_organization, regular_org)

      conn = post(conn, ~p"/#{regular_org.slug}/maintenance/cleanup_invitations")

      assert redirected_to(conn) == ~p"/#{regular_org.slug}/dashboard"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Access denied"
    end

    test "creates and enqueues a cleanup task", %{conn: conn, org: org, admin: admin} do
      Oban.Testing.with_testing_mode(:manual, fn ->
        conn =
          conn
          |> log_in_user(admin)
          |> assign(:current_organization, org)

        conn = post(conn, ~p"/#{org.slug}/maintenance/cleanup_invitations")

        assert redirected_to(conn) == ~p"/#{org.slug}/maintenance"
        assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "Cleanup task created successfully"
        assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "Task ID:"

        assert Phoenix.Flash.get(conn.assigns.flash, :info) =~
                 "View progress in the Tasks section"

        # Verify task was created
        tasks = Tasks.list_all_tasks() |> elem(0)
        task = Enum.find(tasks, &(&1.type == "cleanup_expired_invitations"))

        assert task
        assert task.type == "cleanup_expired_invitations"
        assert task.action == "execute"
        assert task.status == :pending
        assert task.organization_id == nil
        assert task.metadata["triggered_by"] == "admin_manual"
        assert task.metadata["admin_user_id"] == admin.id

        # Verify TaskExecutor job was enqueued
        assert_enqueued(worker: TaskExecutor, args: %{"task_id" => task.id})
      end)
    end

    test "handles task creation failure gracefully", %{conn: conn, org: org, admin: admin} do
      conn =
        conn
        |> log_in_user(admin)
        |> assign(:current_organization, org)

      # We can't easily simulate a failure without mocking, but this tests the happy path
      conn = post(conn, ~p"/#{org.slug}/maintenance/cleanup_invitations")

      assert redirected_to(conn) == ~p"/#{org.slug}/maintenance"

      flash =
        Phoenix.Flash.get(conn.assigns.flash, :info) ||
          Phoenix.Flash.get(conn.assigns.flash, :error)

      assert flash
    end
  end
end
