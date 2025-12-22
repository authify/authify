defmodule AuthifyWeb.Dashboard.GroupControllerTest do
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures

  @create_attrs %{name: "some name", description: "some description", is_active: true}
  @update_attrs %{
    name: "some updated name",
    description: "some updated description",
    is_active: false
  }
  @invalid_attrs %{name: nil, description: nil, is_active: nil}

  describe "index" do
    test "lists all groups", %{conn: conn} do
      conn = get(conn, ~p"/dashboard/groups")
      assert html_response(conn, 200) =~ "Listing Groups"
    end
  end

  describe "new group" do
    test "renders form", %{conn: conn} do
      conn = get(conn, ~p"/dashboard/groups/new")
      assert html_response(conn, 200) =~ "New Group"
    end
  end

  describe "create group" do
    test "redirects to show when data is valid", %{conn: conn} do
      conn = post(conn, ~p"/dashboard/groups", group: @create_attrs)

      assert %{id: id} = redirected_params(conn)
      assert redirected_to(conn) == ~p"/dashboard/groups/#{id}"

      conn = get(conn, ~p"/dashboard/groups/#{id}")
      assert html_response(conn, 200) =~ "Group #{id}"
    end

    test "renders errors when data is invalid", %{conn: conn} do
      conn = post(conn, ~p"/dashboard/groups", group: @invalid_attrs)
      assert html_response(conn, 200) =~ "New Group"
    end
  end

  describe "edit group" do
    setup [:create_group]

    test "renders form for editing chosen group", %{conn: conn, group: group} do
      conn = get(conn, ~p"/dashboard/groups/#{group}/edit")
      assert html_response(conn, 200) =~ "Edit Group"
    end
  end

  describe "update group" do
    setup [:create_group]

    test "redirects when data is valid", %{conn: conn, group: group} do
      conn = put(conn, ~p"/dashboard/groups/#{group}", group: @update_attrs)
      assert redirected_to(conn) == ~p"/dashboard/groups/#{group}"

      conn = get(conn, ~p"/dashboard/groups/#{group}")
      assert html_response(conn, 200) =~ "some updated name"
    end

    test "renders errors when data is invalid", %{conn: conn, group: group} do
      conn = put(conn, ~p"/dashboard/groups/#{group}", group: @invalid_attrs)
      assert html_response(conn, 200) =~ "Edit Group"
    end
  end

  describe "delete group" do
    setup [:create_group]

    test "deletes chosen group", %{conn: conn, group: group} do
      conn = delete(conn, ~p"/dashboard/groups/#{group}")
      assert redirected_to(conn) == ~p"/dashboard/groups"

      assert_error_sent 404, fn ->
        get(conn, ~p"/dashboard/groups/#{group}")
      end
    end
  end

  defp create_group(_) do
    group = group_fixture()

    %{group: group}
  end
end
