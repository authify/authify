defmodule AuthifyWeb.GroupControllerTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures
  import Authify.OAuthFixtures
  import Authify.SAMLFixtures

  alias Authify.Groups

  setup %{conn: conn} do
    organization = organization_fixture()
    admin_user = user_fixture(organization: organization, role: "admin")

    conn =
      conn
      |> log_in_user(admin_user)
      |> assign(:current_user, admin_user)
      |> assign(:current_organization, organization)

    %{conn: conn, admin_user: admin_user, organization: organization}
  end

  describe "manage_members/2" do
    test "lists assigned applications by name, not ID", %{
      conn: conn,
      organization: organization
    } do
      group = group_fixture(organization: organization)
      oauth_app = application_fixture(organization: organization, name: "Named OAuth App")
      saml_sp = service_provider_fixture(organization: organization, name: "Named SAML SP")

      {:ok, _} = Groups.add_application_to_group(group, oauth_app.id, "oauth2")
      {:ok, _} = Groups.add_application_to_group(group, saml_sp.id, "saml")

      conn = get(conn, ~p"/#{organization.slug}/groups/#{group.id}/members")

      html = html_response(conn, 200)
      assert html =~ "Named OAuth App"
      assert html =~ "Named SAML SP"
      refute html =~ "ID: #{oauth_app.id}"
      refute html =~ "ID: #{saml_sp.id}"
    end

    test "excludes already assigned applications from the add dropdowns", %{
      conn: conn,
      organization: organization
    } do
      group = group_fixture(organization: organization)
      assigned = application_fixture(organization: organization, name: "Already Assigned")
      available = application_fixture(organization: organization, name: "Still Available")

      {:ok, _} = Groups.add_application_to_group(group, assigned.id, "oauth2")

      conn = get(conn, ~p"/#{organization.slug}/groups/#{group.id}/members")

      html = html_response(conn, 200)
      assert html =~ ~s(<option value="#{available.id}">Still Available</option>)
      refute html =~ ~s(<option value="#{assigned.id}">Already Assigned</option>)
    end

    test "labels unresolvable applications with type and ID", %{
      conn: conn,
      organization: organization
    } do
      group = group_fixture(organization: organization)

      {:ok, _} =
        %Authify.Accounts.GroupApplication{}
        |> Authify.Accounts.GroupApplication.changeset(%{
          group_id: group.id,
          application_id: 999_999,
          application_type: "oauth2"
        })
        |> Authify.Repo.insert()

      conn = get(conn, ~p"/#{organization.slug}/groups/#{group.id}/members")

      assert html_response(conn, 200) =~ "Unknown oauth2 application (999999)"
    end

    test "hides the add form when no applications are available", %{
      conn: conn,
      organization: organization
    } do
      group = group_fixture(organization: organization)

      conn = get(conn, ~p"/#{organization.slug}/groups/#{group.id}/members")

      html = html_response(conn, 200)
      assert html =~ "No OAuth applications available to add."
      assert html =~ "No SAML service providers available to add."
      refute html =~ ~s(<option value="">Select OAuth app...)
    end
  end

  describe "add_application/2" do
    test "adds an application to the group", %{conn: conn, organization: organization} do
      group = group_fixture(organization: organization)
      oauth_app = application_fixture(organization: organization)

      conn =
        post(conn, ~p"/#{organization.slug}/groups/#{group.id}/applications", %{
          application_id: oauth_app.id,
          application_type: "oauth2"
        })

      assert redirected_to(conn) == ~p"/#{organization.slug}/groups/#{group.id}/members"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "added"

      members =
        Groups.get_group!(group.id, organization) |> Authify.Repo.preload(:group_applications)

      assert Enum.any?(members.group_applications, &(&1.application_id == oauth_app.id))
    end

    test "rejects a duplicate application without raising", %{
      conn: conn,
      organization: organization
    } do
      group = group_fixture(organization: organization)
      oauth_app = application_fixture(organization: organization)
      {:ok, _} = Groups.add_application_to_group(group, oauth_app.id, "oauth2")

      conn =
        post(conn, ~p"/#{organization.slug}/groups/#{group.id}/applications", %{
          application_id: oauth_app.id,
          application_type: "oauth2"
        })

      assert redirected_to(conn) == ~p"/#{organization.slug}/groups/#{group.id}/members"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "already in this group"

      members =
        Groups.get_group!(group.id, organization) |> Authify.Repo.preload(:group_applications)

      assert length(members.group_applications) == 1
    end

    test "rejects a blank application id without raising", %{
      conn: conn,
      organization: organization
    } do
      group = group_fixture(organization: organization)

      conn =
        post(conn, ~p"/#{organization.slug}/groups/#{group.id}/applications", %{
          application_id: "",
          application_type: "oauth2"
        })

      assert redirected_to(conn) == ~p"/#{organization.slug}/groups/#{group.id}/members"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Failed to add application"
    end

    test "rejects an application belonging to another organization", %{
      conn: conn,
      organization: organization
    } do
      group = group_fixture(organization: organization)
      other_org = organization_fixture()
      foreign_app = application_fixture(organization: other_org)

      conn =
        post(conn, ~p"/#{organization.slug}/groups/#{group.id}/applications", %{
          application_id: foreign_app.id,
          application_type: "oauth2"
        })

      assert redirected_to(conn) == ~p"/#{organization.slug}/groups/#{group.id}/members"

      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~
               "does not exist in this organization"

      members =
        Groups.get_group!(group.id, organization) |> Authify.Repo.preload(:group_applications)

      assert members.group_applications == []
    end
  end
end
