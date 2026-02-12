defmodule AuthifyWeb.TaskLive.ShowTest do
  use AuthifyWeb.ConnCase, async: false

  import Phoenix.LiveViewTest
  import Authify.AccountsFixtures

  alias Authify.Tasks

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

  describe "Task Show LiveView" do
    @tag :capture_log
    test "displays task details", %{conn: conn, org: org, admin: admin} do
      # Create a task
      {:ok, task} =
        Tasks.create_and_enqueue_task(%{
          type: "test_task",
          action: "execute",
          organization_id: org.id,
          params: %{"test" => "value"},
          status: :completed
        })

      {:ok, view, _html} =
        conn
        |> log_in_user(admin)
        |> live(~p"/#{org.slug}/tasks/#{task.id}")

      assert has_element?(view, "h1", "Task Details")
      assert has_element?(view, "td", "test_task")
      assert has_element?(view, "td", "execute")
    end

    test "displays task logs", %{conn: conn, org: org, admin: admin} do
      # Create a task
      {:ok, task} =
        Tasks.create_and_enqueue_task(%{
          type: "test_task",
          action: "execute",
          organization_id: org.id,
          params: %{},
          status: :pending
        })

      # Add some logs
      Tasks.create_task_log(task, "Log message 1")
      Tasks.create_task_log(task, "Log message 2")

      {:ok, view, _html} =
        conn
        |> log_in_user(admin)
        |> live(~p"/#{org.slug}/tasks/#{task.id}")

      assert has_element?(view, "h5", "Execution Logs")
      assert render(view) =~ "Log message 1"
      assert render(view) =~ "Log message 2"
      assert has_element?(view, ".badge", "2 log entries")
    end

    @tag :capture_log
    test "shows empty state when no logs exist", %{conn: conn, org: org, admin: admin} do
      # Create a task without logs
      {:ok, task} =
        Tasks.create_and_enqueue_task(%{
          type: "test_task",
          action: "execute",
          organization_id: org.id,
          params: %{},
          status: :completed
        })

      {:ok, view, _html} =
        conn
        |> log_in_user(admin)
        |> live(~p"/#{org.slug}/tasks/#{task.id}")

      assert has_element?(view, "h5", "Execution Logs")
      assert render(view) =~ "No logs available"
    end

    test "cancels task when cancel button clicked", %{conn: conn, org: org, admin: admin} do
      # Create a pending task (without enqueuing to keep it in pending state)
      {:ok, task} =
        Tasks.create_task(%{
          type: "test_task",
          action: "execute",
          organization_id: org.id,
          params: %{},
          status: :pending
        })

      {:ok, view, _html} =
        conn
        |> log_in_user(admin)
        |> live(~p"/#{org.slug}/tasks/#{task.id}")

      # Should show cancel button for pending task
      assert has_element?(view, "button", "Cancel Task")

      # Click cancel
      view |> element("button", "Cancel Task") |> render_click()

      # Verify task was cancelled
      updated_task = Tasks.get_task!(task.id)
      assert updated_task.status == :cancelled
    end
  end
end
