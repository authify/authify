defmodule Authify.OAuthTest do
  use Authify.DataCase

  alias Authify.OAuth
  import Authify.AccountsFixtures

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
end
