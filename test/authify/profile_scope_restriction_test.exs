defmodule Authify.ProfileScopeRestrictionTest do
  use Authify.DataCase

  alias Authify.Accounts
  alias Authify.OAuth
  import Authify.AccountsFixtures

  describe "profile scope restrictions" do
    test "OAuth applications cannot request profile:read or profile:write scopes" do
      organization = organization_fixture()

      oauth_app_attrs = %{
        name: "Test OAuth App",
        description: "Test app",
        scopes: "openid profile:read email",
        redirect_uris: "https://example.com/callback",
        organization_id: organization.id,
        application_type: "oauth2_app"
      }

      assert {:error, changeset} = OAuth.create_application(oauth_app_attrs)
      assert changeset.errors[:scopes] == {"contains invalid scopes: profile:read", []}

      oauth_app_attrs_write = %{
        name: "Test OAuth App",
        description: "Test app",
        scopes: "openid profile:write email",
        redirect_uris: "https://example.com/callback",
        organization_id: organization.id,
        application_type: "oauth2_app"
      }

      assert {:error, changeset} = OAuth.create_application(oauth_app_attrs_write)
      assert changeset.errors[:scopes] == {"contains invalid scopes: profile:write", []}
    end

    test "Management API applications cannot request profile:read or profile:write scopes" do
      organization = organization_fixture()

      mgmt_app_attrs = %{
        name: "Test Management API App",
        description: "Test app",
        scopes: "management_app:read profile:read",
        organization_id: organization.id,
        application_type: "management_api_app"
      }

      assert {:error, changeset} = OAuth.create_application(mgmt_app_attrs)
      assert changeset.errors[:scopes] == {"contains invalid scopes: profile:read", []}
    end

    test "OAuth applications can request standard profile scope" do
      organization = organization_fixture()

      oauth_app_attrs = %{
        name: "Test OAuth App",
        description: "Test app",
        scopes: "openid profile email",
        redirect_uris: "https://example.com/callback",
        organization_id: organization.id,
        application_type: "oauth2_app"
      }

      assert {:ok, application} = OAuth.create_application(oauth_app_attrs)
      assert "profile" in OAuth.Application.scopes_list(application)
    end

    test "Personal Access Tokens can request profile:read and profile:write scopes" do
      user = user_fixture()
      organization = organization_fixture()

      pat_attrs = %{
        "name" => "Test PAT",
        "scopes" => "profile:read profile:write"
      }

      assert {:ok, pat} = Accounts.create_personal_access_token(user, organization, pat_attrs)
      assert "profile:read" in Accounts.PersonalAccessToken.scopes_list(pat)
      assert "profile:write" in Accounts.PersonalAccessToken.scopes_list(pat)
    end
  end
end
