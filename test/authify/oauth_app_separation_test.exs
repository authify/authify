defmodule Authify.OAuthAppSeparationTest do
  use Authify.DataCase

  alias Authify.OAuth
  import Authify.AccountsFixtures

  describe "OAuth and Management API app separation" do
    setup do
      organization = organization_fixture()

      # Create a regular OAuth app
      {:ok, oauth_app} =
        OAuth.create_application(%{
          name: "OAuth Test App",
          description: "Test OAuth app",
          scopes: "openid profile email",
          redirect_uris: "https://example.com/callback",
          organization_id: organization.id,
          application_type: "oauth2_app"
        })

      # Create a Management API app
      {:ok, mgmt_app} =
        OAuth.create_application(%{
          name: "Management API Test App",
          description: "Test Management API app",
          scopes: "management_app:read users:write",
          organization_id: organization.id,
          application_type: "management_api_app"
        })

      %{organization: organization, oauth_app: oauth_app, mgmt_app: mgmt_app}
    end

    test "list_oauth_applications only returns OAuth apps", %{
      organization: organization,
      oauth_app: oauth_app
    } do
      oauth_apps = OAuth.list_oauth_applications(organization)

      assert length(oauth_apps) == 1
      assert hd(oauth_apps).id == oauth_app.id
      assert hd(oauth_apps).application_type == "oauth2_app"
    end

    test "list_management_api_applications only returns Management API apps", %{
      organization: organization,
      mgmt_app: mgmt_app
    } do
      mgmt_apps = OAuth.list_management_api_applications(organization)

      assert length(mgmt_apps) == 1
      assert hd(mgmt_apps).id == mgmt_app.id
      assert hd(mgmt_apps).application_type == "management_api_app"
    end

    test "get_oauth_application! only finds OAuth apps", %{
      organization: organization,
      oauth_app: oauth_app,
      mgmt_app: mgmt_app
    } do
      # Should find OAuth app
      found_oauth_app = OAuth.get_oauth_application!(oauth_app.id, organization)
      assert found_oauth_app.id == oauth_app.id

      # Should not find Management API app
      assert_raise Ecto.NoResultsError, fn ->
        OAuth.get_oauth_application!(mgmt_app.id, organization)
      end
    end

    test "get_management_api_application! only finds Management API apps", %{
      organization: organization,
      oauth_app: oauth_app,
      mgmt_app: mgmt_app
    } do
      # Should find Management API app
      found_mgmt_app = OAuth.get_management_api_application!(mgmt_app.id, organization)
      assert found_mgmt_app.id == mgmt_app.id

      # Should not find OAuth app
      assert_raise Ecto.NoResultsError, fn ->
        OAuth.get_management_api_application!(oauth_app.id, organization)
      end
    end

    test "paginated list functions work correctly", %{organization: organization} do
      {oauth_apps, oauth_total} =
        OAuth.list_oauth_applications(organization, page: 1, per_page: 10)

      {mgmt_apps, mgmt_total} =
        OAuth.list_management_api_applications(organization, page: 1, per_page: 10)

      assert length(oauth_apps) == 1
      assert oauth_total == 1
      assert hd(oauth_apps).application_type == "oauth2_app"

      assert length(mgmt_apps) == 1
      assert mgmt_total == 1
      assert hd(mgmt_apps).application_type == "management_api_app"
    end
  end
end
