defmodule AuthifyWeb.PasswordResetControllerTest do
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures
  alias Authify.Accounts
  alias Authify.Accounts.User
  alias Authify.AuditLog

  describe "GET /password_reset/new" do
    test "renders password reset request form", %{conn: conn} do
      conn = get(conn, ~p"/password_reset/new")
      response = html_response(conn, 200)
      assert response =~ "Forgot Your Password?"
      assert response =~ "Enter your email address"
    end
  end

  describe "POST /password_reset" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      %{organization: organization, user: user}
    end

    @tag :capture_log
    test "generates reset token for valid email", %{conn: conn, user: user} do
      conn =
        post(conn, ~p"/password_reset", %{
          "password_reset" => %{"email" => User.get_primary_email_value(user)}
        })

      assert redirected_to(conn) == ~p"/login"

      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~
               "If an account with that email exists"

      # Verify token was generated
      updated_user = Accounts.get_user!(user.id)
      assert updated_user.password_reset_token != nil
      assert updated_user.password_reset_expires_at != nil
    end

    test "shows same message for non-existent email (security)", %{conn: conn} do
      conn =
        post(conn, ~p"/password_reset", %{
          "password_reset" => %{"email" => "nonexistent@example.com"}
        })

      assert redirected_to(conn) == ~p"/login"

      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~
               "If an account with that email exists"
    end

    test "handles empty email", %{conn: conn} do
      conn =
        post(conn, ~p"/password_reset", %{
          "password_reset" => %{"email" => ""}
        })

      assert redirected_to(conn) == ~p"/login"

      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~
               "If an account with that email exists"
    end

    test "handles malformed email", %{conn: conn} do
      conn =
        post(conn, ~p"/password_reset", %{
          "password_reset" => %{"email" => "not-an-email"}
        })

      assert redirected_to(conn) == ~p"/login"

      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~
               "If an account with that email exists"
    end
  end

  describe "GET /password_reset/:token/edit" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      {:ok, _updated_user, token} = Accounts.generate_password_reset_token(user)
      %{organization: organization, user: user, token: token}
    end

    test "renders password reset form with valid token", %{conn: conn, token: token} do
      conn = get(conn, ~p"/password_reset/#{token}/edit")
      response = html_response(conn, 200)
      assert response =~ "Reset Your Password"
      assert response =~ "New Password"
      assert response =~ "Confirm New Password"
    end

    test "redirects with error for invalid token", %{conn: conn} do
      conn = get(conn, ~p"/password_reset/invalid-token/edit")
      assert redirected_to(conn) == ~p"/password_reset/new"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Password reset link is invalid"
    end

    test "redirects with error for expired token", %{conn: conn, user: user} do
      # Create expired token
      expired_time = DateTime.add(DateTime.utc_now(), -1, :hour) |> DateTime.truncate(:second)
      expired_token = Accounts.User.generate_password_reset_token()

      user
      |> Ecto.Changeset.change(%{
        password_reset_token: expired_token,
        password_reset_expires_at: expired_time
      })
      |> Authify.Repo.update!()

      conn = get(conn, ~p"/password_reset/#{expired_token}/edit")
      assert redirected_to(conn) == ~p"/password_reset/new"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Password reset link is invalid"
    end
  end

  describe "PUT /password_reset/:token" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      {:ok, _updated_user, token} = Accounts.generate_password_reset_token(user)
      %{organization: organization, user: user, token: token}
    end

    test "resets password with valid token and params", %{
      conn: conn,
      token: token,
      user: user,
      organization: organization
    } do
      password_params = %{
        "password" => "NewSecureP@ssw0rd!",
        "password_confirmation" => "NewSecureP@ssw0rd!"
      }

      conn =
        put(conn, ~p"/password_reset/#{token}", %{
          "user" => password_params
        })

      assert redirected_to(conn) == ~p"/login"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "Password reset successfully"

      # Verify password was changed
      updated_user = Accounts.get_user!(user.id)
      assert Accounts.User.valid_password?(updated_user, "NewSecureP@ssw0rd!")
      refute Accounts.User.valid_password?(updated_user, "SecureP@ssw0rd!")

      # Verify token was cleared
      assert updated_user.password_reset_token == nil
      assert updated_user.password_reset_expires_at == nil

      events =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "password_reset_completed"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "success"
      assert event.metadata["source"] == "web"
      assert event.metadata["user_id"] == user.id
    end

    test "shows error for invalid token", %{conn: conn} do
      password_params = %{
        "password" => "NewSecureP@ssw0rd!",
        "password_confirmation" => "NewSecureP@ssw0rd!"
      }

      conn =
        put(conn, ~p"/password_reset/invalid-token", %{
          "user" => password_params
        })

      assert redirected_to(conn) == ~p"/password_reset/new"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Password reset link is invalid"
    end

    test "shows error for expired token", %{conn: conn, user: user, organization: organization} do
      # Create expired token
      expired_time = DateTime.add(DateTime.utc_now(), -1, :hour) |> DateTime.truncate(:second)
      plaintext_token = Accounts.User.generate_password_reset_token()
      hashed_token = Accounts.User.hash_password_reset_token(plaintext_token)

      user
      |> Ecto.Changeset.change(%{
        password_reset_token: hashed_token,
        password_reset_expires_at: expired_time
      })
      |> Authify.Repo.update!()

      password_params = %{
        "password" => "NewSecureP@ssw0rd!",
        "password_confirmation" => "NewSecureP@ssw0rd!"
      }

      conn =
        put(conn, ~p"/password_reset/#{plaintext_token}", %{
          "user" => password_params
        })

      assert redirected_to(conn) == ~p"/password_reset/new"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Password reset link has expired"

      events =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "password_reset_completed"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "failure"
      assert event.metadata["reason"] == "token_expired"
      assert event.metadata["user_id"] == user.id
    end

    test "renders form with errors for invalid password", %{
      conn: conn,
      token: token,
      user: user,
      organization: organization
    } do
      invalid_password_params = %{
        "password" => "weak",
        "password_confirmation" => "different"
      }

      conn =
        put(conn, ~p"/password_reset/#{token}", %{
          "user" => invalid_password_params
        })

      response = html_response(conn, 200)
      assert response =~ "Reset Your Password"
      # Should render the form again with validation errors

      events =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "password_reset_completed"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "failure"
      assert event.metadata["reason"] == "validation_failed"
      assert event.metadata["user_id"] == user.id
      assert Enum.any?(event.metadata["errors"], &String.contains?(&1, "password"))
    end

    test "renders form with errors for mismatched passwords", %{
      conn: conn,
      token: token,
      user: user,
      organization: organization
    } do
      mismatched_password_params = %{
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "DifferentP@ssw0rd!"
      }

      conn =
        put(conn, ~p"/password_reset/#{token}", %{
          "user" => mismatched_password_params
        })

      response = html_response(conn, 200)
      assert response =~ "Reset Your Password"
      # Should render the form again with validation errors

      events =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "password_reset_completed"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "failure"
      assert event.metadata["reason"] == "validation_failed"
      assert event.metadata["user_id"] == user.id
      assert Enum.any?(event.metadata["errors"], &String.contains?(&1, "password"))
    end

    test "renders form with errors for weak password", %{
      conn: conn,
      token: token,
      user: user,
      organization: organization
    } do
      weak_password_params = %{
        "password" => "123",
        "password_confirmation" => "123"
      }

      conn =
        put(conn, ~p"/password_reset/#{token}", %{
          "user" => weak_password_params
        })

      response = html_response(conn, 200)
      assert response =~ "Reset Your Password"
      # Should render the form again with validation errors

      events =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "password_reset_completed"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "failure"
      assert event.metadata["reason"] == "validation_failed"
      assert event.metadata["user_id"] == user.id
      assert Enum.any?(event.metadata["errors"], &String.contains?(&1, "password"))
    end
  end

  describe "security considerations" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      %{organization: organization, user: user}
    end

    test "token cannot be reused after successful reset", %{conn: conn, user: user} do
      {:ok, _updated_user, token} = Accounts.generate_password_reset_token(user)

      # First reset - should succeed
      password_params = %{
        "password" => "NewSecureP@ssw0rd!",
        "password_confirmation" => "NewSecureP@ssw0rd!"
      }

      conn1 =
        put(conn, ~p"/password_reset/#{token}", %{
          "user" => password_params
        })

      assert redirected_to(conn1) == ~p"/login"
      assert Phoenix.Flash.get(conn1.assigns.flash, :info) =~ "Password reset successfully"

      # Second reset attempt with same token - should fail
      conn2 =
        put(conn, ~p"/password_reset/#{token}", %{
          "user" => password_params
        })

      assert redirected_to(conn2) == ~p"/password_reset/new"
      assert Phoenix.Flash.get(conn2.assigns.flash, :error) =~ "Password reset link is invalid"
    end

    test "multiple reset requests generate different tokens", %{user: user} do
      {:ok, _user1, token1} = Accounts.generate_password_reset_token(user)
      {:ok, _user2, token2} = Accounts.generate_password_reset_token(user)

      assert token1 != token2
    end

    test "reset tokens are URL-safe", %{user: user} do
      {:ok, _updated_user, token} = Accounts.generate_password_reset_token(user)

      # Should not contain URL-unsafe characters
      refute String.contains?(token, "+")
      refute String.contains?(token, "/")
      refute String.contains?(token, "=")
    end
  end
end
