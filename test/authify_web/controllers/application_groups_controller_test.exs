defmodule AuthifyWeb.ApplicationGroupsControllerTest do
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures
  import Ecto.Query

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
    test "lists all application groups", %{conn: conn, organization: organization} do
      conn = get(conn, ~p"/#{organization.slug}/application_groups")
      assert html_response(conn, 200) =~ "Application Groups"
    end

    test "shows empty state when no groups exist", %{conn: conn, organization: organization} do
      conn = get(conn, ~p"/#{organization.slug}/application_groups")
      response = html_response(conn, 200)
      assert response =~ "No application groups found"
      assert response =~ "Create your first application group"
    end

    test "displays existing groups", %{conn: conn, organization: organization} do
      group = application_group_fixture(organization: organization)
      conn = get(conn, ~p"/#{organization.slug}/application_groups")
      response = html_response(conn, 200)
      assert response =~ group.name
    end

    test "only shows groups for current organization", %{conn: conn, organization: organization} do
      # Create a group for this organization
      group = application_group_fixture(organization: organization)

      # Create a group for another organization
      other_org = organization_fixture()
      other_group = application_group_fixture(organization: other_org)

      conn = get(conn, ~p"/#{organization.slug}/application_groups")
      response = html_response(conn, 200)

      assert response =~ group.name
      refute response =~ other_group.name
    end
  end

  describe "new" do
    test "renders form", %{conn: conn, organization: organization} do
      conn = get(conn, ~p"/#{organization.slug}/application_groups/new")
      assert html_response(conn, 200) =~ "New Application Group"
    end
  end

  describe "create" do
    test "redirects to show when data is valid", %{conn: conn, organization: organization} do
      create_attrs = %{
        name: "Engineering Team",
        description: "Engineering department access",
        is_active: true
      }

      conn =
        post(conn, ~p"/#{organization.slug}/application_groups", application_group: create_attrs)

      assert %{id: id} = redirected_params(conn)
      assert redirected_to(conn) == ~p"/#{organization.slug}/application_groups/#{id}"

      conn = get(conn, ~p"/#{organization.slug}/application_groups/#{id}")
      response = html_response(conn, 200)
      assert response =~ "Engineering Team"
      assert response =~ "Engineering department access"
    end

    test "renders errors when data is invalid", %{conn: conn, organization: organization} do
      conn =
        post(conn, ~p"/#{organization.slug}/application_groups", application_group: %{})

      assert html_response(conn, 200) =~ "New Application Group"
    end

    test "renders errors when name is missing", %{conn: conn, organization: organization} do
      conn =
        post(conn, ~p"/#{organization.slug}/application_groups",
          application_group: %{name: "", description: "Test"}
        )

      assert html_response(conn, 200) =~ "New Application Group"
    end

    test "associates group with correct organization", %{
      conn: conn,
      organization: organization
    } do
      create_attrs = %{
        name: "Test Group",
        description: "Test description",
        is_active: true
      }

      conn =
        post(conn, ~p"/#{organization.slug}/application_groups", application_group: create_attrs)

      assert %{id: id} = redirected_params(conn)

      group = Authify.Accounts.get_application_group!(id)
      assert group.organization_id == organization.id
    end

    test "prevents duplicate group names in same organization", %{
      conn: conn,
      organization: organization
    } do
      # Create first group
      group = application_group_fixture(organization: organization, name: "Duplicate Name")

      # Try to create another group with same name
      conn =
        post(conn, ~p"/#{organization.slug}/application_groups",
          application_group: %{name: group.name, description: "Different description"}
        )

      assert html_response(conn, 200) =~ "already exists"
    end
  end

  describe "show" do
    setup [:create_application_group]

    test "displays application group", %{
      conn: conn,
      application_group: group,
      organization: organization
    } do
      conn = get(conn, ~p"/#{organization.slug}/application_groups/#{group}")
      response = html_response(conn, 200)
      assert response =~ group.name
      assert response =~ group.description
    end

    test "displays group statistics", %{
      conn: conn,
      application_group: group,
      organization: organization
    } do
      conn = get(conn, ~p"/#{organization.slug}/application_groups/#{group}")
      response = html_response(conn, 200)
      # Should show user and application counts
      assert response =~ "Users"
      assert response =~ "Applications"
    end

    test "only shows groups from current organization", %{conn: conn, organization: organization} do
      other_org = organization_fixture()
      other_group = application_group_fixture(organization: other_org)

      assert_error_sent 404, fn ->
        get(conn, ~p"/#{organization.slug}/application_groups/#{other_group.id}")
      end
    end
  end

  describe "edit" do
    setup [:create_application_group]

    test "renders form for editing chosen application group", %{
      conn: conn,
      application_group: group,
      organization: organization
    } do
      conn = get(conn, ~p"/#{organization.slug}/application_groups/#{group}/edit")
      response = html_response(conn, 200)
      assert response =~ "Edit Application Group"
      assert response =~ group.name
    end

    test "returns 404 for groups from other organizations", %{
      conn: conn,
      organization: organization
    } do
      other_org = organization_fixture()
      other_group = application_group_fixture(organization: other_org)

      assert_error_sent 404, fn ->
        get(conn, ~p"/#{organization.slug}/application_groups/#{other_group.id}/edit")
      end
    end
  end

  describe "update" do
    setup [:create_application_group]

    test "redirects when data is valid", %{
      conn: conn,
      application_group: group,
      organization: organization
    } do
      update_attrs = %{
        name: "Updated Team Name",
        description: "Updated description",
        is_active: false
      }

      conn =
        put(conn, ~p"/#{organization.slug}/application_groups/#{group}",
          application_group: update_attrs
        )

      assert redirected_to(conn) == ~p"/#{organization.slug}/application_groups/#{group}"

      conn = get(conn, ~p"/#{organization.slug}/application_groups/#{group}")
      response = html_response(conn, 200)
      assert response =~ "Updated Team Name"
      assert response =~ "Updated description"
    end

    test "renders errors when data is invalid", %{
      conn: conn,
      application_group: group,
      organization: organization
    } do
      conn =
        put(conn, ~p"/#{organization.slug}/application_groups/#{group}",
          application_group: %{name: ""}
        )

      assert html_response(conn, 200) =~ "Edit Application Group"
    end

    test "cannot update group from another organization", %{
      conn: conn,
      organization: organization
    } do
      other_org = organization_fixture()
      other_group = application_group_fixture(organization: other_org)

      assert_error_sent 404, fn ->
        put(conn, ~p"/#{organization.slug}/application_groups/#{other_group.id}",
          application_group: %{name: "Hacked Name"}
        )
      end
    end
  end

  describe "delete" do
    setup [:create_application_group]

    test "deletes chosen application group", %{
      conn: conn,
      application_group: group,
      organization: organization
    } do
      conn = delete(conn, ~p"/#{organization.slug}/application_groups/#{group}")
      assert redirected_to(conn) == ~p"/#{organization.slug}/application_groups"

      assert_error_sent 404, fn ->
        get(conn, ~p"/#{organization.slug}/application_groups/#{group}")
      end
    end

    test "cannot delete group from another organization", %{
      conn: conn,
      organization: organization
    } do
      other_org = organization_fixture()
      other_group = application_group_fixture(organization: other_org)

      assert_error_sent 404, fn ->
        delete(conn, ~p"/#{organization.slug}/application_groups/#{other_group.id}")
      end

      # Verify the group still exists
      assert Authify.Accounts.get_application_group!(other_group.id)
    end

    test "cascades deletion of user associations", %{
      conn: conn,
      application_group: group,
      organization: organization,
      regular_user: user
    } do
      # Add user to group
      {:ok, _} = Authify.Accounts.add_user_to_application_group(user, group)

      # Delete the group
      delete(conn, ~p"/#{organization.slug}/application_groups/#{group}")

      # Verify user association was deleted (no error when querying)
      user_groups =
        Authify.Repo.all(
          from(uag in Authify.Accounts.UserApplicationGroup,
            where: uag.application_group_id == ^group.id
          )
        )

      assert Enum.empty?(user_groups)
    end
  end

  defp create_application_group(%{organization: organization}) do
    application_group = application_group_fixture(organization: organization)
    %{application_group: application_group}
  end
end
