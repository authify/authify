defmodule AuthifyWeb.HealthControllerTest do
  use AuthifyWeb.ConnCase

  setup do
    # Clear the cache before each test
    cache_table = :health_check_cache

    if :ets.whereis(cache_table) != :undefined do
      :ets.delete_all_objects(cache_table)
    end

    :ok
  end

  describe "GET /health" do
    test "returns healthy status when database is connected", %{conn: conn} do
      conn = get(conn, ~p"/health")

      response = json_response(conn, 200)

      assert response["status"] == "healthy"
      assert response["database"] == "connected"
      assert response["cached"] == true
      assert response["timestamp"] != nil
    end

    test "endpoint is accessible without authentication", %{conn: conn} do
      # Don't set up any authentication - just make the request
      conn = get(conn, ~p"/health")

      assert conn.status == 200
      assert json_response(conn, 200)["status"] == "healthy"
    end

    test "returns JSON content type", %{conn: conn} do
      conn = get(conn, ~p"/health")

      assert get_resp_header(conn, "content-type") == ["application/json; charset=utf-8"]
    end

    test "caches response for 1 second", %{conn: conn} do
      # First request
      conn1 = get(conn, ~p"/health")
      response1 = json_response(conn1, 200)
      timestamp1 = response1["timestamp"]

      # Immediate second request should return cached response with same timestamp
      conn2 = get(build_conn(), ~p"/health")
      response2 = json_response(conn2, 200)
      timestamp2 = response2["timestamp"]

      assert timestamp1 == timestamp2
      assert response2["cached"] == true
    end

    test "refreshes cache after TTL expires", %{conn: conn} do
      # First request
      conn1 = get(conn, ~p"/health")
      response1 = json_response(conn1, 200)
      timestamp1 = response1["timestamp"]

      # Wait for cache to expire (1 second + small buffer)
      Process.sleep(1100)

      # Second request should get fresh data
      conn2 = get(build_conn(), ~p"/health")
      response2 = json_response(conn2, 200)
      timestamp2 = response2["timestamp"]

      # Timestamps should be different since cache expired
      assert timestamp1 != timestamp2
      assert response2["cached"] == true
    end

    test "handles concurrent requests safely", %{conn: _conn} do
      # Spawn multiple concurrent requests to test ETS race conditions
      tasks =
        for _ <- 1..10 do
          Task.async(fn ->
            conn = build_conn()
            get(conn, ~p"/health")
          end)
        end

      results = Task.await_many(tasks)

      # All requests should succeed
      Enum.each(results, fn conn ->
        assert conn.status == 200
        response = json_response(conn, 200)
        assert response["status"] == "healthy"
      end)
    end
  end
end
