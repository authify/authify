defmodule AuthifyWeb.OrganizationControllerTest do
  use AuthifyWeb.ConnCase

  alias Authify.Accounts
  alias Authify.Configurations

  setup do
    # Enable organization registration for tests
    Configurations.set_global_setting(:allow_organization_registration, true)
    :ok
  end

  describe "GET /signup" do
    test "displays organization signup form", %{conn: conn} do
      conn = get(conn, ~p"/signup")
      assert html_response(conn, 200) =~ "Create Your Organization"
      assert html_response(conn, 200) =~ "Organization Name"
      assert html_response(conn, 200) =~ "Admin Account"
    end
  end

  describe "POST /signup" do
    test "creates organization and admin user with valid data", %{conn: conn} do
      org_params = %{
        "name" => "Test Organization",
        "slug" => "test-org"
      }

      user_params = %{
        "first_name" => "John",
        "last_name" => "Doe",
        "email" => "john@test.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      signup_params = %{
        "organization" => org_params,
        "user" => user_params
      }

      conn = post(conn, ~p"/signup", signup: signup_params)

      assert redirected_to(conn) =~ "/organizations/"
      assert redirected_to(conn) =~ "/success"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "Organization created successfully"

      # Verify organization was created
      org = Accounts.get_organization_by_slug("test-org")
      assert org.name == "Test Organization"

      # Verify admin user was created
      user = Accounts.get_user_by_email_and_organization("john@test.com", org.id)
      assert user.first_name == "John"
      assert user.last_name == "Doe"
      assert user.role == "admin"
      assert user.organization_id == org.id
    end

    test "shows errors with invalid organization data", %{conn: conn} do
      org_params = %{
        # Invalid: blank name
        "name" => "",
        # Invalid: blank slug
        "slug" => "",
        "domain" => "test.com"
      }

      user_params = %{
        "first_name" => "John",
        "last_name" => "Doe",
        "email" => "john@test.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      signup_params = %{
        "organization" => org_params,
        "user" => user_params
      }

      conn = post(conn, ~p"/signup", signup: signup_params)

      assert html_response(conn, 200) =~ "Create Your Organization"
      assert html_response(conn, 200) =~ "can&#39;t be blank"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "error creating your organization"
    end

    test "shows errors with invalid user data", %{conn: conn} do
      org_params = %{
        "name" => "Test Organization",
        "slug" => "test-org",
        "domain" => "test.com"
      }

      user_params = %{
        "first_name" => "John",
        "last_name" => "Doe",
        # Invalid email format
        "email" => "invalid-email",
        # Too short
        "password" => "123",
        # Doesn't match
        "password_confirmation" => "456"
      }

      signup_params = %{
        "organization" => org_params,
        "user" => user_params
      }

      conn = post(conn, ~p"/signup", signup: signup_params)

      assert html_response(conn, 200) =~ "Create Your Organization"
      assert html_response(conn, 200) =~ "invalid-feedback"
    end

    test "prevents duplicate organization slugs", %{conn: conn} do
      # Create first organization
      {:ok, _org} = Accounts.create_organization(%{name: "First Org", slug: "test-org"})

      # Try to create second organization with same slug
      org_params = %{
        "name" => "Second Organization",
        # Duplicate slug
        "slug" => "test-org",
        "domain" => "second.com"
      }

      user_params = %{
        "first_name" => "Jane",
        "last_name" => "Smith",
        "email" => "jane@second.com",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      }

      signup_params = %{
        "organization" => org_params,
        "user" => user_params
      }

      conn = post(conn, ~p"/signup", signup: signup_params)

      assert html_response(conn, 200) =~ "Create Your Organization"
      assert html_response(conn, 200) =~ "has already been taken"
    end
  end

  describe "GET /organizations/:id/success" do
    test "displays success page for existing organization", %{conn: conn} do
      {:ok, org} = Accounts.create_organization(%{name: "Success Org", slug: "success-org"})

      conn = get(conn, ~p"/organizations/#{org.id}/success")

      assert html_response(conn, 200) =~ "Welcome to Authify!"
      assert html_response(conn, 200) =~ "Success Org"
      assert html_response(conn, 200) =~ "has been created successfully"
    end

    test "returns 404 for non-existent organization", %{conn: conn} do
      assert_error_sent 404, fn ->
        get(conn, ~p"/organizations/999/success")
      end
    end
  end
end
