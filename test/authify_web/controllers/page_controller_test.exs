defmodule AuthifyWeb.PageControllerTest do
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures
  alias Authify.Accounts

  describe "GET /" do
    test "redirects to setup when no users exist", %{conn: conn} do
      # Ensure no users exist by cleaning up any test data
      :ok = Ecto.Adapters.SQL.Sandbox.checkout(Authify.Repo)
      Ecto.Adapters.SQL.Sandbox.mode(Authify.Repo, {:shared, self()})

      # Delete all users to simulate fresh system
      Authify.Repo.delete_all(Accounts.User)

      conn = get(conn, ~p"/")
      assert redirected_to(conn) == ~p"/setup"
    end

    test "redirects to login when users exist but user not authenticated", %{conn: conn} do
      # Create a user to ensure users exist
      user_fixture()

      conn = get(conn, ~p"/")
      assert redirected_to(conn) == ~p"/login"
    end

    test "redirects to dashboard when user is authenticated", %{conn: conn} do
      # Create user and organization
      organization = organization_fixture()
      user = admin_user_fixture(organization)

      # Authenticate the user
      conn =
        conn
        |> Plug.Test.init_test_session(%{})
        |> Authify.Guardian.Plug.sign_in(user)
        |> AuthifyWeb.Auth.OrganizationContext.call([])

      conn = get(conn, ~p"/")
      assert redirected_to(conn) == ~p"/#{organization.slug}/dashboard"
    end
  end
end
