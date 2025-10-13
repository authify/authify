defmodule AuthifyWeb.ProfileControllerTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  alias Authify.Accounts
  alias Authify.Accounts.PersonalAccessToken
  alias Authify.AuditLog

  setup :register_and_log_in_user

  describe "profile" do
    test "successful profile update logs audit event", %{conn: conn, user: user} do
      params = %{
        "first_name" => "Updated",
        "last_name" => "User",
        "username" => user.username
      }

      conn =
        patch(conn, ~p"/#{user.organization.slug}/profile", %{
          "user" => params
        })

      assert redirected_to(conn) == ~p"/#{user.organization.slug}/profile"

      events =
        AuditLog.list_events(
          organization_id: user.organization_id,
          event_type: "user_updated"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "success"
      assert event.metadata["source"] == "web"
      assert event.metadata["user_id"] == user.id

      assert Enum.any?(event.metadata["changes"], fn change ->
               change["field"] == "first_name" && change["new"] == "Updated"
             end)
    end

    test "failed profile update logs failure", %{conn: conn, user: user} do
      conn =
        patch(conn, ~p"/#{user.organization.slug}/profile", %{
          "user" => %{"email" => ""}
        })

      assert html_response(conn, 200)

      events =
        AuditLog.list_events(
          organization_id: user.organization_id,
          event_type: "user_updated"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "failure"
      assert event.metadata["source"] == "web"
      assert Enum.any?(event.metadata["errors"], &String.contains?(&1, "email"))
    end
  end

  describe "password" do
    test "successful password update logs audit event", %{conn: conn, user: user} do
      params = %{
        "current_password" => "SecureP@ssw0rd!",
        "password" => "NewP@ss1word!",
        "password_confirmation" => "NewP@ss1word!"
      }

      conn =
        patch(conn, ~p"/#{user.organization.slug}/profile/password", %{
          "user" => params
        })

      assert redirected_to(conn) == ~p"/#{user.organization.slug}/profile"

      events =
        AuditLog.list_events(
          organization_id: user.organization_id,
          event_type: "password_changed"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "success"
      assert event.metadata["source"] == "web"
      assert event.metadata["method"] == "self_service"
      assert event.metadata["user_id"] == user.id
    end

    test "invalid current password logs failure", %{conn: conn, user: user} do
      params = %{
        "current_password" => "wrong-password",
        "password" => "AnotherP@ss1!",
        "password_confirmation" => "AnotherP@ss1!"
      }

      conn =
        patch(conn, ~p"/#{user.organization.slug}/profile/password", %{
          "user" => params
        })

      assert html_response(conn, 200)

      events =
        AuditLog.list_events(
          organization_id: user.organization_id,
          event_type: "password_changed"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "failure"
      assert event.metadata["source"] == "web"
      assert Enum.any?(event.metadata["errors"], &String.contains?(&1, "current_password"))
    end
  end

  describe "personal_access_tokens" do
    test "renders personal access tokens page", %{conn: conn, user: user} do
      org = user.organization
      conn = get(conn, ~p"/#{org.slug}/profile/personal-access-tokens")
      response = html_response(conn, 200)
      assert response =~ "Personal Access Tokens"
      assert response =~ "Create New Token"
      assert response =~ "No personal access tokens"
    end

    test "creates personal access token successfully", %{conn: conn, user: user} do
      organization = user.organization

      pat_params = %{
        "name" => "Test API Token",
        "description" => "Token for testing",
        "scopes" => ["profile:read", "profile:write"]
      }

      conn =
        post(conn, ~p"/#{organization.slug}/profile/personal-access-tokens",
          personal_access_token: pat_params
        )

      assert redirected_to(conn) == ~p"/#{organization.slug}/profile/personal-access-tokens"

      follow_conn =
        conn |> recycle() |> get(~p"/#{organization.slug}/profile/personal-access-tokens")

      response = html_response(follow_conn, 200)

      # Test that the token appears in the list (functionality works)
      assert response =~ "Test API Token"
      assert response =~ "Token for testing"
      assert response =~ "profile:read, profile:write"

      # Verify token was created in database
      tokens = Accounts.list_personal_access_tokens(user)
      assert length(tokens) == 1

      token = hd(tokens)
      assert token.name == "Test API Token"
      assert token.description == "Token for testing"
      assert PersonalAccessToken.scopes_list(token) == ["profile:read", "profile:write"]
      assert token.user_id == user.id
      assert token.organization_id == organization.id

      events =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "personal_access_token_created"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "success"
      assert event.metadata["source"] == "web"
      assert event.metadata["personal_access_token_id"] == token.id
      assert Enum.sort(event.metadata["scopes"]) == ["profile:read", "profile:write"]
    end

    test "shows validation errors for invalid token", %{conn: conn, user: user} do
      org = user.organization

      pat_params = %{
        # Empty name should fail validation
        "name" => "",
        "scopes" => []
      }

      conn =
        post(conn, ~p"/#{org.slug}/profile/personal-access-tokens",
          personal_access_token: pat_params
        )

      response = html_response(conn, 200)
      assert response =~ "can&#39;t be blank"

      events =
        AuditLog.list_events(
          organization_id: org.id,
          event_type: "personal_access_token_created"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "failure"
      assert event.metadata["source"] == "web"
      assert Enum.any?(event.metadata["errors"], &String.contains?(&1, "name"))
    end

    test "deletes personal access token", %{conn: conn, user: user} do
      organization = user.organization

      {:ok, token} =
        Accounts.create_personal_access_token(user, organization, %{
          "name" => "Token to Delete",
          "scopes" => "profile:read"
        })

      conn = delete(conn, ~p"/#{organization.slug}/profile/personal-access-tokens/#{token.id}")

      assert redirected_to(conn) == ~p"/#{organization.slug}/profile/personal-access-tokens"

      follow_conn =
        conn |> recycle() |> get(~p"/#{organization.slug}/profile/personal-access-tokens")

      response = html_response(follow_conn, 200)

      # Test that the page shows no tokens (functionality works)
      assert response =~ "No personal access tokens"

      # Verify token was deleted from database
      tokens = Accounts.list_personal_access_tokens(user)
      assert Enum.empty?(tokens)

      events =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "personal_access_token_deleted"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "success"
      assert event.metadata["source"] == "web"
      assert event.metadata["personal_access_token_id"] == token.id
    end

    test "cannot delete another user's token", %{conn: conn, user: user} do
      org = user.organization
      other_user = user_fixture()
      organization = other_user.organization

      {:ok, other_token} =
        Accounts.create_personal_access_token(other_user, organization, %{
          "name" => "Other User Token",
          "scopes" => "profile:read"
        })

      # This should raise an error since we try to get a token that doesn't belong to current user
      assert_raise Ecto.NoResultsError, fn ->
        delete(conn, ~p"/#{org.slug}/profile/personal-access-tokens/#{other_token.id}")
      end
    end

    test "creates personal access token with invitation scopes", %{conn: conn, user: user} do
      organization = user.organization

      pat_params = %{
        "name" => "Invitations API Token",
        "description" => "Token for managing invitations via API",
        "scopes" => ["invitations:read", "invitations:write", "users:read"]
      }

      conn =
        post(conn, ~p"/#{organization.slug}/profile/personal-access-tokens",
          personal_access_token: pat_params
        )

      assert redirected_to(conn) == ~p"/#{organization.slug}/profile/personal-access-tokens"

      follow_conn =
        conn |> recycle() |> get(~p"/#{organization.slug}/profile/personal-access-tokens")

      response = html_response(follow_conn, 200)

      # Test that the token appears in the list with correct scopes
      assert response =~ "Invitations API Token"
      assert response =~ "Token for managing invitations via API"
      assert response =~ "invitations:read, invitations:write, users:read"

      # Verify token was created in database with correct scopes
      tokens = Accounts.list_personal_access_tokens(user)
      token = Enum.find(tokens, &(&1.name == "Invitations API Token"))

      assert token.name == "Invitations API Token"
      assert token.description == "Token for managing invitations via API"

      assert PersonalAccessToken.scopes_list(token) == [
               "invitations:read",
               "invitations:write",
               "users:read"
             ]

      assert token.user_id == user.id
      assert token.organization_id == organization.id

      # Verify token has the expected scopes
      scopes_list = PersonalAccessToken.scopes_list(token)
      assert "invitations:read" in scopes_list
      assert "invitations:write" in scopes_list
      assert "users:read" in scopes_list

      events =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "personal_access_token_created"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "success"
      assert event.metadata["source"] == "web"

      assert Enum.sort(event.metadata["scopes"]) ==
               ["invitations:read", "invitations:write", "users:read"]
    end
  end
end
