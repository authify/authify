defmodule AuthifyWeb.AppLinkControllerTest do
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

    # Create a group
    {:ok, group} =
      Accounts.create_group(%{
        "name" => "Test Apps",
        "description" => "Test group",
        "organization_id" => organization.id
      })

    # Create a test OAuth application
    {:ok, oauth_app} =
      OAuth.create_application(%{
        "name" => "Test OAuth App",
        "redirect_uris" => "https://example.com/callback",
        "organization_id" => organization.id
      })

    # Create a test SAML service provider
    {:ok, saml_sp} =
      SAML.create_service_provider(%{
        "name" => "Test SAML SP",
        "entity_id" => "https://test.example.com",
        "acs_url" => "https://test.example.com/acs",
        "organization_id" => organization.id,
        "is_active" => true
      })

    # Add applications to group
    {:ok, _} = Accounts.add_application_to_group(group, oauth_app.id, "oauth2")
    {:ok, _} = Accounts.add_application_to_group(group, saml_sp.id, "saml")

    # Authenticate user and preload associations
    user = Accounts.get_user_with_organizations!(user.id)

    # Authenticate user
    conn =
      conn
      |> Authify.Guardian.Plug.sign_in(user)
      |> assign(:current_user, user)
      |> assign(:current_organization, organization)

    %{
      conn: conn,
      user: user,
      organization: organization,
      group: group,
      oauth_app: oauth_app,
      saml_sp: saml_sp
    }
  end

  describe "GET /user/apps/oauth2/:app_id" do
    test "redirects to OAuth authorization when user has access", %{
      conn: conn,
      user: user,
      group: group,
      oauth_app: oauth_app,
      organization: org
    } do
      # Add user to group
      {:ok, _} = Accounts.add_user_to_group(user, group)

      conn = get(conn, ~p"/#{org.slug}/user/apps/oauth2/#{oauth_app.id}")

      redirect_url = redirected_to(conn)
      assert redirect_url =~ "/#{org.slug}/oauth/authorize"
      assert redirect_url =~ "client_id=#{URI.encode_www_form(oauth_app.client_id)}"
    end

    test "redirects to user dashboard when user lacks access", %{
      conn: conn,
      oauth_app: oauth_app,
      organization: org
    } do
      # User not added to group, so no access
      conn = get(conn, ~p"/#{org.slug}/user/apps/oauth2/#{oauth_app.id}")

      assert redirected_to(conn) == "/#{org.slug}/user/dashboard"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Access denied"
    end

    test "redirects to user dashboard for non-existent application", %{
      conn: conn,
      organization: org
    } do
      conn = get(conn, ~p"/#{org.slug}/user/apps/oauth2/99999")

      assert redirected_to(conn) == "/#{org.slug}/user/dashboard"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Access denied"
    end
  end

  describe "GET /user/apps/saml/:sp_id" do
    test "redirects to SAML SSO when user has access", %{
      conn: conn,
      user: user,
      group: group,
      saml_sp: saml_sp,
      organization: org
    } do
      # Add user to group
      {:ok, _} = Accounts.add_user_to_group(user, group)

      conn = get(conn, ~p"/#{org.slug}/user/apps/saml/#{saml_sp.id}")

      assert redirected_to(conn) == "/#{org.slug}/saml/sso?sp_id=#{saml_sp.id}"
    end

    test "redirects to user dashboard when user lacks access", %{
      conn: conn,
      saml_sp: saml_sp,
      organization: org
    } do
      # User not added to group, so no access
      conn = get(conn, ~p"/#{org.slug}/user/apps/saml/#{saml_sp.id}")

      assert redirected_to(conn) == "/#{org.slug}/user/dashboard"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Access denied"
    end
  end
end
