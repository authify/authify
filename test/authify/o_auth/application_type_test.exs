defmodule Authify.OAuth.ApplicationTypeTest do
  use Authify.DataCase

  import Authify.AccountsFixtures
  import Authify.OAuthFixtures

  alias Authify.OAuth
  alias Authify.OAuth.Application

  describe "application types" do
    setup do
      organization = organization_fixture()
      %{organization: organization}
    end

    test "creates oauth2_app with valid attributes", %{organization: organization} do
      attrs = %{
        name: "Test OAuth App",
        description: "A test OAuth application",
        redirect_uris: "https://example.com/callback",
        scopes: "openid profile email",
        application_type: "oauth2_app",
        organization_id: organization.id
      }

      assert {:ok, application} = OAuth.create_application(attrs)
      assert application.application_type == "oauth2_app"
      assert application.name == "Test OAuth App"
      assert Application.scopes_list(application) == ["openid", "profile", "email"]
      assert application.redirect_uris == "https://example.com/callback"
      assert application.client_id
      assert application.client_secret
    end

    test "creates management_api_app with valid attributes", %{organization: organization} do
      attrs = %{
        name: "Test Management API Client",
        description: "A test Management API client",
        redirect_uris: "",
        scopes: "management_app:read users:read",
        application_type: "management_api_app",
        organization_id: organization.id
      }

      assert {:ok, application} = OAuth.create_application(attrs)
      assert application.application_type == "management_api_app"
      assert application.name == "Test Management API Client"
      assert Application.scopes_list(application) == ["management_app:read", "users:read"]
      assert application.redirect_uris == ""
      assert application.client_id
      assert application.client_secret
    end

    test "management_api_app doesn't require redirect_uris", %{organization: organization} do
      attrs = %{
        name: "Test Management API Client",
        scopes: "management_app:read",
        application_type: "management_api_app",
        organization_id: organization.id
      }

      assert {:ok, application} = OAuth.create_application(attrs)
      assert application.application_type == "management_api_app"
      assert application.redirect_uris == ""
    end

    test "oauth2_app requires redirect_uris", %{organization: organization} do
      attrs = %{
        name: "Test OAuth App",
        scopes: "openid profile",
        application_type: "oauth2_app",
        organization_id: organization.id
      }

      assert {:error, changeset} = OAuth.create_application(attrs)
      assert "can't be blank" in errors_on(changeset).redirect_uris
    end

    test "validates management API scopes for management_api_app", %{organization: organization} do
      attrs = %{
        name: "Test Management API Client",
        scopes: "invalid:scope openid",
        application_type: "management_api_app",
        organization_id: organization.id
      }

      assert {:error, changeset} = OAuth.create_application(attrs)
      assert "contains invalid scopes: invalid:scope, openid" in errors_on(changeset).scopes
    end

    test "validates OAuth scopes for oauth2_app", %{organization: organization} do
      attrs = %{
        name: "Test OAuth App",
        redirect_uris: "https://example.com/callback",
        scopes: "management_app:read users:read",
        application_type: "oauth2_app",
        organization_id: organization.id
      }

      # OAuth apps can have management scopes too, so this should work
      assert {:ok, application} = OAuth.create_application(attrs)
      assert Application.scopes_list(application) == ["management_app:read", "users:read"]
    end

    test "defaults to oauth2_app when application_type not specified", %{
      organization: organization
    } do
      attrs = %{
        name: "Test Application",
        redirect_uris: "https://example.com/callback",
        scopes: "openid profile",
        organization_id: organization.id
      }

      assert {:ok, application} = OAuth.create_application(attrs)
      assert application.application_type == "oauth2_app"
    end

    test "rejects invalid application_type", %{organization: organization} do
      attrs = %{
        name: "Test Application",
        redirect_uris: "https://example.com/callback",
        application_type: "invalid_type",
        organization_id: organization.id
      }

      assert {:error, changeset} = OAuth.create_application(attrs)
      assert "is invalid" in errors_on(changeset).application_type
    end
  end

  describe "fixtures" do
    test "application_fixture creates oauth2_app by default" do
      application = application_fixture()
      assert application.application_type == "oauth2_app"
      assert application.redirect_uris != ""
      assert "openid" in Application.scopes_list(application)
    end

    test "management_api_application_fixture creates management_api_app" do
      application = management_api_application_fixture()
      assert application.application_type == "management_api_app"
      assert application.redirect_uris == ""

      assert Enum.any?(
               Application.scopes_list(application),
               &String.starts_with?(&1, "management_app:")
             )
    end
  end
end
