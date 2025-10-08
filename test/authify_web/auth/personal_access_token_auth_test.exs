defmodule AuthifyWeb.Auth.PersonalAccessTokenAuthTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  alias Authify.Accounts

  # Helper function to create a user with PAT for testing
  defp create_user_with_token(scopes \\ "profile:read profile:write") do
    user = user_fixture()
    organization = Accounts.get_organization!(user.organization_id)

    {:ok, token} =
      Accounts.create_personal_access_token(user, organization, %{
        "name" => "Test API Token",
        "scopes" => scopes
      })

    %{user: user, organization: organization, token: token}
  end

  describe "Personal Access Token API authentication" do
    test "authenticates successfully with valid PAT", %{conn: conn} do
      %{token: token, user: user, organization: organization} = create_user_with_token()

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{token.plaintext_token}")
        |> get("/#{organization.slug}/api/profile")

      assert json_response(conn, 200)
      response = json_response(conn, 200)
      assert response["data"]["attributes"]["email"] == user.email
    end

    test "rejects invalid PAT", %{conn: conn} do
      %{organization: organization} = create_user_with_token()

      conn =
        conn
        |> put_req_header("authorization", "Bearer authify_pat_invalid_token")
        |> get("/#{organization.slug}/api/profile")

      assert json_response(conn, 401)
      response = json_response(conn, 401)
      assert response["error"]["type"] == "authentication_required"
    end

    test "rejects malformed PAT", %{conn: conn} do
      %{organization: organization} = create_user_with_token()

      conn =
        conn
        |> put_req_header("authorization", "Bearer invalid_token_format")
        |> get("/#{organization.slug}/api/profile")

      assert json_response(conn, 401)
    end

    test "updates last_used_at when token is used", %{conn: conn} do
      %{token: token, user: user, organization: organization} = create_user_with_token()

      # Ensure last_used_at is initially nil
      assert is_nil(token.last_used_at)

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{token.plaintext_token}")
        |> get("/#{organization.slug}/api/profile")

      assert json_response(conn, 200)

      # Check that last_used_at was updated
      updated_token = Accounts.get_personal_access_token!(token.id, user)
      assert updated_token.last_used_at
      assert DateTime.diff(DateTime.utc_now(), updated_token.last_used_at, :second) < 5
    end

    test "respects token expiration", %{conn: conn} do
      %{user: user, organization: organization} = create_user_with_token()

      # Create an expired token
      yesterday = DateTime.utc_now() |> DateTime.add(-1, :day) |> DateTime.truncate(:second)

      {:ok, expired_token} =
        Accounts.create_personal_access_token(user, organization, %{
          "name" => "Expired Token",
          "scopes" => "profile:read",
          "expires_at" => yesterday
        })

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{expired_token.plaintext_token}")
        |> get("/#{organization.slug}/api/profile")

      assert json_response(conn, 401)
      response = json_response(conn, 401)
      assert response["error"]["type"] == "authentication_required"
    end

    test "works with read scope for GET requests", %{conn: conn} do
      %{token: read_token, organization: organization} = create_user_with_token("profile:read")

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{read_token.plaintext_token}")
        |> get("/#{organization.slug}/api/profile")

      assert json_response(conn, 200)
    end

    test "API auth preserves user context", %{conn: conn} do
      %{token: token, user: user, organization: organization} = create_user_with_token()

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{token.plaintext_token}")
        |> get("/#{organization.slug}/api/profile")

      response = json_response(conn, 200)
      user_data = response["data"]
      user_attrs = user_data["attributes"]
      assert user_data["id"] == to_string(user.id)
      assert user_attrs["email"] == user.email
      assert user_attrs["first_name"] == user.first_name
      assert user_attrs["last_name"] == user.last_name
    end
  end
end
