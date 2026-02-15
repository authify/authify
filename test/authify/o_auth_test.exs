defmodule Authify.OAuthTest do
  use Authify.DataCase

  alias Authify.OAuth
  import Authify.AccountsFixtures
  import Authify.OAuthFixtures

  describe "applications" do
    alias Authify.OAuth.Application

    import Authify.OAuthFixtures

    @invalid_attrs %{
      name: nil,
      description: nil,
      scopes: nil,
      redirect_uris: nil,
      organization_id: nil
    }

    test "list_applications/1 returns all applications for an organization" do
      organization = organization_fixture()
      application = application_fixture(organization: organization)
      applications = OAuth.list_applications(organization)
      assert length(applications) == 1
      assert hd(applications).id == application.id
    end

    test "get_application!/2 returns the application with given id and organization" do
      organization = organization_fixture()
      application = application_fixture(organization: organization)
      found_application = OAuth.get_application!(application.id, organization)
      assert found_application.id == application.id
      assert found_application.name == application.name
      assert found_application.organization_id == organization.id
    end

    test "create_application/1 with valid data creates a application" do
      organization = organization_fixture()

      valid_attrs = %{
        name: "some name",
        description: "some description",
        scopes: "openid profile email",
        redirect_uris: "https://example.com/callback",
        organization_id: organization.id
      }

      assert {:ok, %Application{} = application} = OAuth.create_application(valid_attrs)
      assert application.name == "some name"
      assert application.description == "some description"
      assert Application.scopes_list(application) == ["openid", "profile", "email"]
      assert application.redirect_uris == "https://example.com/callback"
      assert application.organization_id == organization.id
      assert is_binary(application.client_id)
      assert is_binary(application.client_secret)
    end

    test "create_application/1 with invalid data returns error changeset" do
      assert {:error, %Ecto.Changeset{}} = OAuth.create_application(@invalid_attrs)
    end

    test "update_application/2 with valid data updates the application" do
      organization = organization_fixture()
      application = application_fixture(organization: organization)

      update_attrs = %{
        name: "some updated name",
        description: "some updated description",
        scopes: "openid profile",
        redirect_uris: "https://updated.example.com/callback"
      }

      assert {:ok, %Application{} = updated_application} =
               OAuth.update_application(application, update_attrs)

      assert updated_application.name == "some updated name"
      assert updated_application.description == "some updated description"
      assert Application.scopes_list(updated_application) == ["openid", "profile"]
      assert updated_application.redirect_uris == "https://updated.example.com/callback"
      # Client credentials should not change during update
      assert updated_application.client_id == application.client_id
      assert updated_application.client_secret == application.client_secret
    end

    test "update_application/2 with invalid data returns error changeset" do
      organization = organization_fixture()
      application = application_fixture(organization: organization)
      assert {:error, %Ecto.Changeset{}} = OAuth.update_application(application, @invalid_attrs)
      found_application = OAuth.get_application!(application.id, organization)
      assert found_application.id == application.id
      assert found_application.name == application.name
    end

    test "delete_application/1 deletes the application" do
      organization = organization_fixture()
      application = application_fixture(organization: organization)
      assert {:ok, %Application{}} = OAuth.delete_application(application)

      assert_raise Ecto.NoResultsError, fn ->
        OAuth.get_application!(application.id, organization)
      end
    end

    test "change_application/1 returns a application changeset" do
      organization = organization_fixture()
      application = application_fixture(organization: organization)
      assert %Ecto.Changeset{} = OAuth.change_application(application)
    end
  end

  describe "user grants" do
    setup do
      org = organization_fixture()
      user = user_for_organization_fixture(org)
      app = application_fixture(organization: org)
      %{org: org, user: user, app: app}
    end

    test "create_or_update_user_grant/3 creates new grant", %{user: user, app: app} do
      assert {:ok, grant} = OAuth.create_or_update_user_grant(user, app, ["openid", "profile"])

      assert grant.user_id == user.id
      assert grant.application_id == app.id
      assert grant.scopes == "openid profile"
      assert is_nil(grant.revoked_at)
    end

    test "create_or_update_user_grant/3 accepts scopes as string", %{user: user, app: app} do
      assert {:ok, grant} = OAuth.create_or_update_user_grant(user, app, "openid profile email")

      assert grant.scopes == "openid profile email"
    end

    test "create_or_update_user_grant/3 updates existing grant scopes", %{user: user, app: app} do
      {:ok, grant} = OAuth.create_or_update_user_grant(user, app, ["openid"])

      assert grant.scopes == "openid"

      # Update with more scopes
      {:ok, updated_grant} =
        OAuth.create_or_update_user_grant(user, app, ["openid", "profile", "email"])

      assert updated_grant.id == grant.id
      assert updated_grant.scopes == "openid profile email"
    end

    test "create_or_update_user_grant/3 un-revokes revoked grant", %{user: user, app: app} do
      {:ok, grant} = OAuth.create_or_update_user_grant(user, app, ["openid"])
      {:ok, revoked_grant} = OAuth.revoke_user_grant(grant)

      assert revoked_grant.revoked_at

      # Re-grant should un-revoke
      {:ok, renewed_grant} = OAuth.create_or_update_user_grant(user, app, ["openid", "profile"])

      assert renewed_grant.id == grant.id
      assert is_nil(renewed_grant.revoked_at)
      assert renewed_grant.scopes == "openid profile"
    end

    test "get_user_grant/2 returns active grant", %{user: user, app: app} do
      {:ok, created_grant} = OAuth.create_or_update_user_grant(user, app, ["openid"])

      grant = OAuth.get_user_grant(user, app)

      assert grant.id == created_grant.id
      assert grant.user_id == user.id
      assert grant.application_id == app.id
    end

    test "get_user_grant/2 returns nil for non-existent grant", %{user: user, app: app} do
      assert is_nil(OAuth.get_user_grant(user, app))
    end

    test "get_user_grant/2 returns nil for revoked grant", %{user: user, app: app} do
      {:ok, grant} = OAuth.create_or_update_user_grant(user, app, ["openid"])
      {:ok, _} = OAuth.revoke_user_grant(grant)

      assert is_nil(OAuth.get_user_grant(user, app))
    end

    test "list_user_grants/1 returns all active grants for user", %{user: user, org: org} do
      app1 = application_fixture(organization: org, name: "App 1")
      app2 = application_fixture(organization: org, name: "App 2")

      {:ok, _} = OAuth.create_or_update_user_grant(user, app1, ["openid"])
      {:ok, _} = OAuth.create_or_update_user_grant(user, app2, ["openid", "profile"])

      grants = OAuth.list_user_grants(user)

      assert length(grants) == 2
      assert Enum.any?(grants, &(&1.application_id == app1.id))
      assert Enum.any?(grants, &(&1.application_id == app2.id))
    end

    test "list_user_grants/1 excludes revoked grants", %{user: user, org: org} do
      app1 = application_fixture(organization: org, name: "App 1")
      app2 = application_fixture(organization: org, name: "App 2")

      {:ok, grant1} = OAuth.create_or_update_user_grant(user, app1, ["openid"])
      {:ok, _grant2} = OAuth.create_or_update_user_grant(user, app2, ["openid"])

      {:ok, _} = OAuth.revoke_user_grant(grant1)

      grants = OAuth.list_user_grants(user)

      assert length(grants) == 1
      assert hd(grants).application_id == app2.id
    end

    test "list_user_grants/1 orders by most recently updated first", %{user: user, org: org} do
      app1 = application_fixture(organization: org, name: "App 1")
      app2 = application_fixture(organization: org, name: "App 2")

      {:ok, grant1} = OAuth.create_or_update_user_grant(user, app1, ["openid"])
      Process.sleep(10)
      {:ok, _grant2} = OAuth.create_or_update_user_grant(user, app2, ["openid"])

      # Update grant1 to make it most recent
      Process.sleep(10)
      {:ok, _} = OAuth.create_or_update_user_grant(user, app1, ["openid", "profile"])

      grants = OAuth.list_user_grants(user)

      assert hd(grants).id == grant1.id
    end

    test "revoke_user_grant/1 marks grant as revoked", %{user: user, app: app} do
      {:ok, grant} = OAuth.create_or_update_user_grant(user, app, ["openid"])

      assert is_nil(grant.revoked_at)

      {:ok, revoked_grant} = OAuth.revoke_user_grant(grant)

      refute is_nil(revoked_grant.revoked_at)
    end

    test "validate_user_grant/3 succeeds when grant covers all scopes", %{user: user, app: app} do
      {:ok, _} = OAuth.create_or_update_user_grant(user, app, ["openid", "profile", "email"])

      assert {:ok, grant} = OAuth.validate_user_grant(user, app, ["openid", "profile"])
      assert grant.user_id == user.id
    end

    test "validate_user_grant/3 succeeds when scopes exactly match", %{user: user, app: app} do
      {:ok, _} = OAuth.create_or_update_user_grant(user, app, ["openid", "profile"])

      assert {:ok, _grant} = OAuth.validate_user_grant(user, app, ["openid", "profile"])
    end

    test "validate_user_grant/3 fails with :insufficient_grant when scopes don't match", %{
      user: user,
      app: app
    } do
      {:ok, _} = OAuth.create_or_update_user_grant(user, app, ["openid"])

      assert {:error, :insufficient_grant} =
               OAuth.validate_user_grant(user, app, ["openid", "profile", "email"])
    end

    test "validate_user_grant/3 fails with :no_grant when no grant exists", %{
      user: user,
      app: app
    } do
      assert {:error, :no_grant} = OAuth.validate_user_grant(user, app, ["openid"])
    end

    test "validate_user_grant/3 fails when grant is revoked", %{user: user, app: app} do
      {:ok, grant} = OAuth.create_or_update_user_grant(user, app, ["openid", "profile"])
      {:ok, _} = OAuth.revoke_user_grant(grant)

      assert {:error, :no_grant} = OAuth.validate_user_grant(user, app, ["openid"])
    end
  end
end
