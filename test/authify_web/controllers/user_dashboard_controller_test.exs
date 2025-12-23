defmodule AuthifyWeb.UserDashboardControllerTest do
  use AuthifyWeb.ConnCase

  alias Authify.Accounts
  alias Authify.OAuth
  alias Authify.SAML

  setup %{conn: conn} do
    # Create test organization
    {:ok, organization} =
      Accounts.create_organization(%{
        name: "Test Organization",
        slug: "test-org"
      })

    # Create test user directly in organization
    {:ok, user} =
      Accounts.create_user_with_role(
        %{
          "email" => "user@test.org",
          "username" => "testuser",
          "password" => "SecurePassword123!",
          "password_confirmation" => "SecurePassword123!",
          "first_name" => "Test",
          "last_name" => "User"
        },
        organization.id,
        "user"
      )

    # Authenticate user and preload associations
    user = Accounts.get_user_with_organizations!(user.id)

    conn =
      conn
      |> Authify.Guardian.Plug.sign_in(user)
      |> assign(:current_user, user)
      |> assign(:current_organization, organization)

    %{
      conn: conn,
      user: user,
      organization: organization
    }
  end

  describe "GET /user/dashboard" do
    test "renders user dashboard with no applications when user has no group access", %{
      conn: conn,
      organization: org
    } do
      conn = get(conn, ~p"/#{org.slug}/user/dashboard")

      assert html_response(conn, 200)
      assert html_response(conn, 200) =~ "My Applications"
      assert html_response(conn, 200) =~ "No Applications Available"
    end

    test "shows accessible applications when user has group access", %{
      conn: conn,
      user: user,
      organization: org
    } do
      # Create a group
      {:ok, group} =
        Accounts.create_group(%{
          "name" => "Test Apps",
          "description" => "Test group",
          "organization_id" => org.id
        })

      # Create a test OAuth application
      {:ok, oauth_app} =
        OAuth.create_application(%{
          name: "Test OAuth App",
          description: "A test OAuth application",
          organization_id: org.id,
          redirect_uris: "https://example.com/callback"
        })

      # Create a test SAML service provider
      {:ok, saml_sp} =
        SAML.create_service_provider(%{
          "name" => "Test SAML SP",
          "entity_id" => "https://test.example.com",
          "acs_url" => "https://test.example.com/acs",
          "organization_id" => org.id,
          "is_active" => true
        })

      # Add applications to group
      {:ok, _} = Accounts.add_application_to_group(group, oauth_app.id, "oauth2")
      {:ok, _} = Accounts.add_application_to_group(group, saml_sp.id, "saml")

      # Add user to group
      {:ok, _} = Accounts.add_user_to_group(user, group)

      conn = get(conn, ~p"/#{org.slug}/user/dashboard")

      assert html_response(conn, 200)
      assert html_response(conn, 200) =~ "Test OAuth App"
      assert html_response(conn, 200) =~ "Test SAML SP"
      assert html_response(conn, 200) =~ "/user/apps/oauth2/#{oauth_app.id}"
      assert html_response(conn, 200) =~ "/user/apps/saml/#{saml_sp.id}"
    end
  end
end
