defmodule AuthifyWeb.API.TasksControllerTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  alias Authify.Tasks

  # --- Setup ---

  setup %{conn: conn} do
    organization = organization_fixture()
    admin_user = user_fixture(organization: organization, role: "admin")

    # Create test tasks
    {:ok, task1} =
      Tasks.create_task(%{
        type: "email",
        action: "send_invitation",
        params: %{"user_id" => "123"},
        organization_id: organization.id
      })

    {:ok, task2} =
      Tasks.create_task(%{
        type: "scim",
        action: "sync_user",
        params: %{"user_id" => "456"},
        organization_id: organization.id
      })

    # Transition task2 to running
    {:ok, running_task} = Tasks.transition_task(task2, :running)

    # Add a log entry
    Tasks.create_task_log(task1, "Task created via test")

    conn =
      conn
      |> put_req_header("accept", "application/vnd.authify.v1+json")
      |> put_req_header("content-type", "application/vnd.authify.v1+json")
      |> log_in_user(admin_user)
      |> assign(:current_user, admin_user)
      |> assign(:current_organization, organization)
      |> assign(:api_authenticated, true)
      |> assign(:current_scopes, ["tasks:read", "tasks:write"])

    %{
      conn: conn,
      organization: organization,
      admin_user: admin_user,
      task1: task1,
      task2: running_task
    }
  end

  # --- Index Tests ---

  describe "GET /api/tasks" do
    test "returns paginated list of tasks", %{conn: conn, organization: org} do
      conn = get(conn, "/#{org.slug}/api/tasks")

      assert %{
               "data" => tasks,
               "links" => %{"self" => _},
               "meta" => %{"total" => 2, "page" => 1, "per_page" => 25}
             } = json_response(conn, 200)

      assert length(tasks) == 2

      Enum.each(tasks, fn task ->
        assert %{"id" => _, "type" => "task", "attributes" => _, "links" => _} = task
      end)
    end

    test "filters by status", %{conn: conn, organization: org} do
      conn = get(conn, "/#{org.slug}/api/tasks?status=pending")

      assert %{"data" => tasks, "meta" => %{"total" => 1}} = json_response(conn, 200)
      assert length(tasks) == 1
      assert hd(tasks)["attributes"]["status"] == "pending"
    end

    test "filters by type", %{conn: conn, organization: org} do
      conn = get(conn, "/#{org.slug}/api/tasks?type=email")

      assert %{"data" => tasks, "meta" => %{"total" => 1}} = json_response(conn, 200)
      assert length(tasks) == 1
      assert hd(tasks)["attributes"]["type"] == "email"
    end

    test "filters by action", %{conn: conn, organization: org} do
      conn = get(conn, "/#{org.slug}/api/tasks?action=sync_user")

      assert %{"data" => tasks, "meta" => %{"total" => 1}} = json_response(conn, 200)
      assert length(tasks) == 1
      assert hd(tasks)["attributes"]["action"] == "sync_user"
    end

    test "supports pagination", %{conn: conn, organization: org} do
      conn = get(conn, "/#{org.slug}/api/tasks?page=1&per_page=1")

      assert %{"data" => tasks, "meta" => %{"total" => 2, "per_page" => 1}} =
               json_response(conn, 200)

      assert length(tasks) == 1
    end

    test "requires tasks:read scope", %{conn: conn, organization: org} do
      conn = conn |> assign(:current_scopes, ["profile:read"])
      conn = get(conn, "/#{org.slug}/api/tasks")

      assert %{"error" => %{"type" => "insufficient_scope"}} = json_response(conn, 403)
    end

    test "does not return tasks from other organizations", %{conn: conn, organization: org} do
      other_org = organization_fixture()

      {:ok, _other_task} =
        Tasks.create_task(%{
          type: "email",
          action: "other_org_task",
          organization_id: other_org.id
        })

      # Request with the current org's slug — controller filters by current_organization
      conn = get(conn, "/#{org.slug}/api/tasks")

      assert %{"data" => tasks} = json_response(conn, 200)

      # Should only see the current org's tasks, not other_org's
      Enum.each(tasks, fn task ->
        refute task["attributes"]["action"] == "other_org_task"
      end)
    end
  end

  # --- Show Tests ---

  describe "GET /api/tasks/:id" do
    test "returns task details", %{conn: conn, organization: org, task1: task1} do
      conn = get(conn, "/#{org.slug}/api/tasks/#{task1.id}")

      assert %{
               "data" => %{
                 "id" => id,
                 "type" => "task",
                 "attributes" => attributes,
                 "links" => %{"self" => _}
               }
             } = json_response(conn, 200)

      assert id == task1.id
      assert attributes["type"] == "email"
      assert attributes["action"] == "send_invitation"
      assert attributes["status"] == "pending"
    end

    test "returns 404 for non-existent task", %{conn: conn, organization: org} do
      conn = get(conn, "/#{org.slug}/api/tasks/#{Ecto.UUID.generate()}")

      assert %{"error" => %{"type" => "resource_not_found"}} = json_response(conn, 404)
    end

    test "returns 404 for task in different organization", %{conn: conn, organization: org} do
      other_org = organization_fixture()

      {:ok, other_task} =
        Tasks.create_task(%{
          type: "email",
          action: "other_task",
          organization_id: other_org.id
        })

      conn = get(conn, "/#{org.slug}/api/tasks/#{other_task.id}")

      assert %{"error" => %{"type" => "resource_not_found"}} = json_response(conn, 404)
    end

    test "requires tasks:read scope", %{conn: conn, organization: org, task1: task1} do
      conn = conn |> assign(:current_scopes, ["profile:read"])
      conn = get(conn, "/#{org.slug}/api/tasks/#{task1.id}")

      assert %{"error" => %{"type" => "insufficient_scope"}} = json_response(conn, 403)
    end
  end

  # --- Logs Tests ---

  describe "GET /api/tasks/:id/logs" do
    test "returns task logs", %{conn: conn, organization: org, task1: task1} do
      conn = get(conn, "/#{org.slug}/api/tasks/#{task1.id}/logs")

      assert %{
               "data" => logs,
               "meta" => %{"total" => 1}
             } = json_response(conn, 200)

      assert length(logs) == 1
      assert hd(logs)["type"] == "task_log"
    end

    test "returns empty list for task with no logs", %{
      conn: conn,
      organization: org,
      task2: task2
    } do
      conn = get(conn, "/#{org.slug}/api/tasks/#{task2.id}/logs")

      assert %{"data" => [], "meta" => %{"total" => 0}} = json_response(conn, 200)
    end

    test "returns 404 for non-existent task", %{conn: conn, organization: org} do
      conn = get(conn, "/#{org.slug}/api/tasks/#{Ecto.UUID.generate()}/logs")

      assert %{"error" => %{"type" => "resource_not_found"}} = json_response(conn, 404)
    end

    test "requires tasks:read scope", %{conn: conn, organization: org, task1: task1} do
      conn = conn |> assign(:current_scopes, ["profile:read"])
      conn = get(conn, "/#{org.slug}/api/tasks/#{task1.id}/logs")

      assert %{"error" => %{"type" => "insufficient_scope"}} = json_response(conn, 403)
    end
  end

  # --- Cancel Tests ---

  describe "POST /api/tasks/:id/cancel" do
    test "cancels a pending task", %{conn: conn, organization: org, task1: task1} do
      conn = post(conn, "/#{org.slug}/api/tasks/#{task1.id}/cancel")

      assert %{
               "data" => %{
                 "attributes" => %{"status" => "cancelled"}
               }
             } = json_response(conn, 200)
    end

    test "cancels a running task", %{conn: conn, organization: org, task2: task2} do
      conn = post(conn, "/#{org.slug}/api/tasks/#{task2.id}/cancel")

      assert %{
               "data" => %{
                 "attributes" => %{"status" => "cancelled"}
               }
             } = json_response(conn, 200)
    end

    test "rejects cancellation of already-cancelled task", %{conn: conn, organization: org} do
      {:ok, task} =
        Tasks.create_task(%{
          type: "email",
          action: "test_cancel",
          organization_id: org.id
        })

      {:ok, _} = Tasks.cancel_task(task)

      conn = post(conn, "/#{org.slug}/api/tasks/#{task.id}/cancel")

      assert %{"error" => %{"type" => "invalid_state_transition"}} =
               json_response(conn, 422)
    end

    test "rejects cancellation of completed task", %{conn: conn, organization: org} do
      {:ok, task} =
        Tasks.create_task(%{
          type: "email",
          action: "test_completed",
          organization_id: org.id
        })

      {:ok, running} = Tasks.transition_task(task, :running)
      {:ok, completing} = Tasks.transition_task(running, :completing)
      {:ok, _completed} = Tasks.transition_task(completing, :completed)

      conn = post(conn, "/#{org.slug}/api/tasks/#{task.id}/cancel")

      assert %{"error" => %{"type" => "invalid_state_transition"}} =
               json_response(conn, 422)
    end

    test "returns 404 for non-existent task", %{conn: conn, organization: org} do
      conn = post(conn, "/#{org.slug}/api/tasks/#{Ecto.UUID.generate()}/cancel")

      assert %{"error" => %{"type" => "resource_not_found"}} = json_response(conn, 404)
    end

    test "requires tasks:write scope", %{conn: conn, organization: org, task1: task1} do
      conn = conn |> assign(:current_scopes, ["tasks:read"])
      conn = post(conn, "/#{org.slug}/api/tasks/#{task1.id}/cancel")

      assert %{"error" => %{"type" => "insufficient_scope"}} = json_response(conn, 403)
    end

    test "tasks:write scope includes tasks:read", %{conn: conn, organization: org} do
      conn = conn |> assign(:current_scopes, ["tasks:write"])
      conn = get(conn, "/#{org.slug}/api/tasks")

      assert %{"data" => _tasks} = json_response(conn, 200)
    end
  end
end
