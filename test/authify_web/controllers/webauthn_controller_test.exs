defmodule AuthifyWeb.WebAuthnControllerTest do
  use AuthifyWeb.ConnCase

  alias Authify.{Accounts, Repo}
  alias Authify.MFA.{WebAuthn, WebAuthnCredential}

  setup do
    # Create organization
    {:ok, organization} =
      Accounts.create_organization(%{name: "Test Org", slug: "test-org"})

    # Create user
    user_attrs = %{
      "first_name" => "John",
      "last_name" => "Doe",
      "email" => "john@test.com",
      "password" => "SecureP@ssw0rd!",
      "password_confirmation" => "SecureP@ssw0rd!"
    }

    {:ok, user} = Accounts.create_user_with_role(user_attrs, organization.id, "user")

    # Reload user with organization
    user = Repo.preload(user, :organization)

    %{organization: organization, user: user}
  end

  # ============================================================================
  # Setup Flow Tests
  # ============================================================================

  describe "GET /:org_slug/profile/webauthn/setup" do
    test "displays WebAuthn setup page", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      conn =
        conn
        |> log_in_user(user, organization)
        |> get(~p"/#{organization.slug}/profile/webauthn/setup")

      assert html_response(conn, 200) =~ "Register Security Key or Passkey"
      assert html_response(conn, 200) =~ "Choose your authenticator type"
      # Should have the WebAuthn registration script
      assert html_response(conn, 200) =~ "WebAuthnRegistration"
    end

    test "shows credential count", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      # Create a credential for the user
      create_credential(user, %{name: "Test Key"})

      conn =
        conn
        |> log_in_user(user, organization)
        |> get(~p"/#{organization.slug}/profile/webauthn/setup")

      # The template says "You already have 1 security key registered"
      assert html_response(conn, 200) =~ "You already have"
      assert html_response(conn, 200) =~ "1 security"
    end

    test "requires authentication", %{conn: conn, organization: organization} do
      conn = get(conn, ~p"/#{organization.slug}/profile/webauthn/setup")

      assert redirected_to(conn) == ~p"/login"
    end
  end

  describe "POST /:org_slug/profile/webauthn/register/begin" do
    test "returns registration challenge and options", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      conn =
        conn
        |> log_in_user(user, organization)
        |> post(~p"/#{organization.slug}/profile/webauthn/register/begin", %{})

      response = json_response(conn, 200)
      assert response["success"] == true
      assert response["options"]
      assert response["options"]["challenge"]
      assert response["options"]["rp"]
      assert response["options"]["user"]

      # Verify challenge is stored in session
      challenge = get_session(conn, :webauthn_registration_challenge)
      assert is_binary(challenge)
    end

    test "accepts authenticator attachment parameter", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      conn =
        conn
        |> log_in_user(user, organization)
        |> post(~p"/#{organization.slug}/profile/webauthn/register/begin", %{
          "authenticatorAttachment" => "platform"
        })

      response = json_response(conn, 200)
      assert response["success"] == true

      assert response["options"]["authenticatorSelection"]["authenticatorAttachment"] ==
               "platform"
    end

    test "requires authentication", %{conn: conn, organization: organization} do
      conn = post(conn, ~p"/#{organization.slug}/profile/webauthn/register/begin", %{})

      assert redirected_to(conn) == ~p"/login"
    end
  end

  describe "POST /:org_slug/profile/webauthn/register/complete" do
    setup %{conn: conn, organization: organization, user: user} do
      # Begin registration to get challenge
      conn =
        conn
        |> log_in_user(user, organization)
        |> post(~p"/#{organization.slug}/profile/webauthn/register/begin", %{})

      challenge = get_session(conn, :webauthn_registration_challenge)

      %{conn: conn, challenge: challenge}
    end

    test "returns error without active challenge", %{
      organization: organization,
      user: user
    } do
      # Create new conn without challenge in session
      conn =
        build_conn()
        |> log_in_user(user, organization)
        |> post(~p"/#{organization.slug}/profile/webauthn/register/complete", %{
          "attestationResponse" => %{},
          "credentialName" => "Test Key"
        })

      response = json_response(conn, 400)
      assert response["success"] == false
      assert response["error"] =~ "No active registration challenge"
    end

    @tag :capture_log
    test "requires credential name", %{
      conn: conn,
      organization: organization,
      challenge: challenge
    } do
      # This will fail at the WebAuthn verification level, but we're just testing
      # that the controller accepts the parameters
      conn =
        post(conn, ~p"/#{organization.slug}/profile/webauthn/register/complete", %{
          "attestationResponse" => %{
            "id" => "test_id",
            "response" => %{
              "attestationObject" => Base.encode64("fake"),
              "clientDataJSON" => Base.encode64(~s({"challenge":"#{challenge}"}))
            }
          },
          "credentialName" => "My YubiKey"
        })

      # Will fail at WebAuthn verification, but that's expected
      assert json_response(conn, 422)
    end

    test "requires authentication", %{organization: organization} do
      conn =
        build_conn()
        |> post(~p"/#{organization.slug}/profile/webauthn/register/complete", %{})

      assert redirected_to(conn) == ~p"/login"
    end
  end

  # ============================================================================
  # Credential Management Tests
  # ============================================================================

  describe "GET /:org_slug/profile/webauthn" do
    test "lists user's WebAuthn credentials", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      # Create some credentials
      create_credential(user, %{name: "YubiKey 5", credential_id: "yubikey_123"})
      create_credential(user, %{name: "Touch ID", credential_id: "touchid_456"})

      conn =
        conn
        |> log_in_user(user, organization)
        |> get(~p"/#{organization.slug}/profile/webauthn")

      assert html_response(conn, 200) =~ "Security Keys"
      assert html_response(conn, 200) =~ "Passkeys"
      assert html_response(conn, 200) =~ "YubiKey 5"
      assert html_response(conn, 200) =~ "Touch ID"
    end

    test "shows empty state when no credentials", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      conn =
        conn
        |> log_in_user(user, organization)
        |> get(~p"/#{organization.slug}/profile/webauthn")

      assert html_response(conn, 200) =~ "registered any security keys"
    end

    test "requires authentication", %{conn: conn, organization: organization} do
      conn = get(conn, ~p"/#{organization.slug}/profile/webauthn")

      assert redirected_to(conn) == ~p"/login"
    end
  end

  describe "PATCH /:org_slug/profile/webauthn/:id/rename" do
    test "updates credential name", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      credential = create_credential(user, %{name: "Old Name"})

      conn =
        conn
        |> log_in_user(user, organization)
        |> patch(~p"/#{organization.slug}/profile/webauthn/#{credential.id}/rename", %{
          "name" => "New Name"
        })

      response = json_response(conn, 200)
      assert response["success"] == true
      assert response["credential"]["name"] == "New Name"

      # Verify in database
      {:ok, updated} = WebAuthn.get_credential(credential.id)
      assert updated.name == "New Name"
    end

    test "returns error for non-existent credential", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      conn =
        conn
        |> log_in_user(user, organization)
        |> patch(~p"/#{organization.slug}/profile/webauthn/999999/rename", %{
          "name" => "New Name"
        })

      response = json_response(conn, 404)
      assert response["success"] == false
    end

    test "returns error when trying to rename another user's credential", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      # Create another user
      {:ok, other_user} =
        Accounts.create_user_with_role(
          %{
            "first_name" => "Jane",
            "last_name" => "Smith",
            "email" => "jane@test.com",
            "password" => "SecureP@ssw0rd!",
            "password_confirmation" => "SecureP@ssw0rd!"
          },
          organization.id,
          "user"
        )

      other_user = Repo.preload(other_user, :organization)

      # Create credential for other user
      other_credential = create_credential(other_user, %{name: "Other's Key"})

      # Try to rename as current user
      conn =
        conn
        |> log_in_user(user, organization)
        |> patch(~p"/#{organization.slug}/profile/webauthn/#{other_credential.id}/rename", %{
          "name" => "Stolen Name"
        })

      response = json_response(conn, 403)
      assert response["success"] == false
      assert response["error"] =~ "Not authorized"
    end

    test "requires authentication", %{conn: conn, organization: organization} do
      conn = patch(conn, ~p"/#{organization.slug}/profile/webauthn/1/rename", %{})

      assert redirected_to(conn) == ~p"/login"
    end
  end

  describe "DELETE /:org_slug/profile/webauthn/:id" do
    test "revokes a credential", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      credential = create_credential(user, %{name: "To Delete"})

      conn =
        conn
        |> log_in_user(user, organization)
        |> delete(~p"/#{organization.slug}/profile/webauthn/#{credential.id}")

      assert redirected_to(conn) == ~p"/#{organization.slug}/profile/mfa"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "revoked successfully"

      # Verify it's deleted
      assert {:error, :not_found} = WebAuthn.get_credential(credential.id)
    end

    test "returns error when trying to revoke another user's credential", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      # Create another user
      {:ok, other_user} =
        Accounts.create_user_with_role(
          %{
            "first_name" => "Jane",
            "last_name" => "Smith",
            "email" => "jane@test.com",
            "password" => "SecureP@ssw0rd!",
            "password_confirmation" => "SecureP@ssw0rd!"
          },
          organization.id,
          "user"
        )

      other_user = Repo.preload(other_user, :organization)

      # Create credential for other user
      other_credential = create_credential(other_user, %{name: "Other's Key"})

      # Try to delete as current user
      conn =
        conn
        |> log_in_user(user, organization)
        |> delete(~p"/#{organization.slug}/profile/webauthn/#{other_credential.id}")

      assert redirected_to(conn) == ~p"/#{organization.slug}/profile/mfa"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Not authorized"

      # Verify it's not deleted
      assert {:ok, _credential} = WebAuthn.get_credential(other_credential.id)
    end

    test "requires authentication", %{conn: conn, organization: organization} do
      conn = delete(conn, ~p"/#{organization.slug}/profile/webauthn/1")

      assert redirected_to(conn) == ~p"/login"
    end
  end

  describe "DELETE /:org_slug/profile/webauthn" do
    test "revokes all credentials with valid password", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      # Create multiple credentials
      create_credential(user, %{name: "Credential 1"})
      create_credential(user, %{name: "Credential 2"})

      assert length(WebAuthn.list_credentials(user)) == 2

      conn =
        conn
        |> log_in_user(user, organization)
        |> delete(~p"/#{organization.slug}/profile/webauthn", %{
          "password" => "SecureP@ssw0rd!"
        })

      assert redirected_to(conn) == ~p"/#{organization.slug}/profile/mfa"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "All security keys have been revoked"

      # Verify all are deleted
      assert WebAuthn.list_credentials(user) == []
    end

    test "returns error with invalid password", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      create_credential(user, %{name: "Credential 1"})

      conn =
        conn
        |> log_in_user(user, organization)
        |> delete(~p"/#{organization.slug}/profile/webauthn", %{
          "password" => "WrongPassword"
        })

      assert redirected_to(conn) == ~p"/#{organization.slug}/profile/mfa"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Invalid password"

      # Verify credential still exists
      assert length(WebAuthn.list_credentials(user)) == 1
    end

    test "requires password parameter", %{
      conn: conn,
      organization: organization,
      user: user
    } do
      create_credential(user, %{name: "Credential 1"})

      conn =
        conn
        |> log_in_user(user, organization)
        |> delete(~p"/#{organization.slug}/profile/webauthn", %{})

      assert redirected_to(conn) == ~p"/#{organization.slug}/profile/mfa"

      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~
               "Password is required to revoke all security keys"

      # Verify credential still exists
      assert length(WebAuthn.list_credentials(user)) == 1
    end

    test "requires authentication", %{conn: conn, organization: organization} do
      conn = delete(conn, ~p"/#{organization.slug}/profile/webauthn", %{})

      assert redirected_to(conn) == ~p"/login"
    end
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp log_in_user(conn, user, organization) do
    conn
    |> Plug.Test.init_test_session(%{})
    |> Authify.Guardian.Plug.sign_in(user)
    |> Plug.Conn.put_session(:current_organization_id, organization.id)
    |> Plug.Conn.assign(:current_user, user)
    |> Plug.Conn.assign(:current_organization, organization)
  end

  defp create_credential(user, attrs) do
    default_attrs = %{
      user_id: user.id,
      organization_id: user.organization_id,
      credential_id: "test_credential_#{:rand.uniform(100_000)}",
      public_key: :crypto.strong_rand_bytes(32),
      sign_count: 0,
      name: "Test Credential",
      credential_type: "platform"
    }

    %WebAuthnCredential{}
    |> WebAuthnCredential.changeset(Map.merge(default_attrs, attrs))
    |> Repo.insert!()
  end
end
