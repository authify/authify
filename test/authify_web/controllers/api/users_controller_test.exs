defmodule AuthifyWeb.API.UsersControllerTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  alias Authify.Accounts.User

  setup %{conn: conn} do
    organization = organization_fixture()
    admin_user = user_fixture(organization: organization, role: "admin")
    regular_user = user_fixture(organization: organization, role: "user")

    # Set up API headers and authentication as admin
    conn =
      conn
      |> put_req_header("accept", "application/vnd.authify.v1+json")
      |> put_req_header("content-type", "application/vnd.authify.v1+json")
      |> log_in_user(admin_user)
      |> assign(:current_user, admin_user)
      |> assign(:current_organization, organization)
      |> assign(:api_authenticated, true)
      |> assign(:current_scopes, ["users:read", "users:write"])

    %{conn: conn, admin_user: admin_user, regular_user: regular_user, organization: organization}
  end

  describe "GET /api/users" do
    test "returns paginated list of users with HATEOAS", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/api/users")

      assert %{
               "data" => users,
               "links" => %{
                 "self" => self_link,
                 "first" => first_link
               },
               "meta" => %{
                 "total" => 2,
                 "page" => 1,
                 "per_page" => 25
               }
             } = json_response(conn, 200)

      assert self_link == "http://localhost:4002/#{organization.slug}/api/users"

      assert length(users) == 2
      assert String.contains?(first_link, "page=1&per_page=25")

      # Check user structure
      user_data = List.first(users)

      assert %{
               "id" => _,
               "type" => "user",
               "attributes" => attributes,
               "links" => %{"self" => self_link}
             } = user_data

      assert String.starts_with?(self_link, "/#{organization.slug}/api/users/")
      refute Map.has_key?(attributes, "password_hash")
      refute Map.has_key?(attributes, "password_reset_token")
    end

    test "supports pagination parameters", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/api/users?page=1&per_page=1")

      assert %{
               "data" => users,
               "meta" => %{
                 "total" => 2,
                 "page" => 1,
                 "per_page" => 1
               }
             } = json_response(conn, 200)

      assert length(users) == 1
    end

    test "requires appropriate Management API scopes", %{conn: conn, organization: organization} do
      # Set up connection without user scopes
      conn =
        conn
        |> assign(:current_scopes, ["profile:read"])

      conn = get(conn, "/#{organization.slug}/api/users")

      assert %{
               "error" => %{
                 "type" => "insufficient_scope",
                 "message" => "Insufficient scope to access this resource"
               }
             } = json_response(conn, 403)
    end
  end

  describe "GET /api/users/:id" do
    test "returns user details", %{
      conn: conn,
      regular_user: regular_user,
      organization: organization
    } do
      conn = get(conn, "/#{organization.slug}/api/users/#{regular_user.id}")

      assert %{
               "data" => %{
                 "id" => id,
                 "type" => "user",
                 "attributes" => attributes,
                 "links" => %{"self" => self_link}
               }
             } = json_response(conn, 200)

      assert String.starts_with?(self_link, "/#{organization.slug}/api/users/")
      assert id == to_string(regular_user.id)
      assert attributes["primary_email"] == User.get_primary_email_value(regular_user)
    end

    test "returns 404 for non-existent user", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/api/users/99999")

      assert %{
               "error" => %{
                 "type" => "resource_not_found",
                 "message" => "User not found in organization"
               }
             } = json_response(conn, 404)
    end

    test "requires appropriate Management API scopes", %{
      conn: conn,
      regular_user: regular_user,
      organization: organization
    } do
      # Set up connection without user scopes
      conn =
        conn
        |> assign(:current_scopes, ["profile:read"])

      conn = get(conn, "/#{organization.slug}/api/users/#{regular_user.id}")

      assert %{
               "error" => %{
                 "type" => "insufficient_scope",
                 "message" => "Insufficient scope to access this resource"
               }
             } = json_response(conn, 403)
    end
  end

  describe "POST /api/users" do
    test "creates user with valid data", %{conn: conn, organization: organization} do
      user_attrs = %{
        "user" => %{
          "emails" => [
            %{"value" => "newuser@example.com", "primary" => true, "type" => "work"}
          ],
          "first_name" => "New",
          "last_name" => "User",
          "password" => "SecureP@ssw0rd!",
          "password_confirmation" => "SecureP@ssw0rd!"
        }
      }

      conn = post(conn, "/#{organization.slug}/api/users", user_attrs)

      assert %{
               "data" => %{
                 "type" => "user",
                 "attributes" => attributes
               }
             } = json_response(conn, 201)

      assert attributes["primary_email"] == "newuser@example.com"

      assert attributes["first_name"] == "New"
      assert attributes["last_name"] == "User"
    end

    test "returns validation errors for invalid email", %{conn: conn, organization: organization} do
      invalid_attrs = %{
        "user" => %{
          "emails" => [
            %{"value" => "invalid-email"}
          ],
          "password" => "short"
        }
      }

      conn = post(conn, "/#{organization.slug}/api/users", invalid_attrs)

      assert %{
               "error" => %{
                 "type" => "validation_failed",
                 "details" => details
               }
             } = json_response(conn, 422)

      assert details["emails"]
      # Note: password validation only runs when email is valid
    end

    test "returns validation errors for invalid password", %{
      conn: conn,
      organization: organization
    } do
      invalid_attrs = %{
        "user" => %{
          "emails" => [
            %{"value" => "valid@example.com", "primary" => true}
          ],
          "password" => "short"
        }
      }

      conn = post(conn, "/#{organization.slug}/api/users", invalid_attrs)

      assert %{
               "error" => %{
                 "type" => "validation_failed",
                 "details" => details
               }
             } = json_response(conn, 422)

      assert details["password"]
    end

    test "requires appropriate Management API scopes", %{conn: conn, organization: organization} do
      # Set up connection without user scopes
      conn =
        conn
        |> assign(:current_scopes, ["profile:read"])

      user_attrs = %{
        "user" => %{
          "emails" => [
            %{"value" => "newuser@example.com", "primary" => true}
          ],
          "first_name" => "New",
          "last_name" => "User",
          "password" => "SecureP@ssw0rd!",
          "password_confirmation" => "SecureP@ssw0rd!"
        }
      }

      conn = post(conn, "/#{organization.slug}/api/users", user_attrs)

      assert %{
               "error" => %{
                 "type" => "insufficient_scope",
                 "message" => "Insufficient scope to access this resource"
               }
             } = json_response(conn, 403)
    end

    test "returns error for missing user parameters", %{conn: conn, organization: organization} do
      conn = post(conn, "/#{organization.slug}/api/users", %{})

      assert %{
               "error" => %{
                 "type" => "invalid_request",
                 "message" => "Request must include user parameters"
               }
             } = json_response(conn, 400)
    end
  end

  describe "PUT /api/users/:id" do
    test "admin can update any user", %{
      conn: conn,
      regular_user: regular_user,
      organization: organization
    } do
      update_attrs = %{
        "user" => %{
          "first_name" => "Updated",
          "last_name" => "Name"
        }
      }

      conn = put(conn, "/#{organization.slug}/api/users/#{regular_user.id}", update_attrs)

      assert %{
               "data" => %{
                 "attributes" => attributes
               }
             } = json_response(conn, 200)

      assert attributes["first_name"] == "Updated"
      assert attributes["last_name"] == "Name"
    end

    test "user can update their own profile", %{
      regular_user: regular_user,
      organization: organization
    } do
      # Set up connection as regular user
      conn =
        build_conn()
        |> put_req_header("accept", "application/vnd.authify.v1+json")
        |> put_req_header("content-type", "application/vnd.authify.v1+json")
        |> log_in_user(regular_user)
        |> assign(:current_user, regular_user)
        |> assign(:current_organization, organization)
        |> assign(:api_authenticated, true)
        |> assign(:current_scopes, ["users:read", "users:write"])

      update_attrs = %{
        "user" => %{
          "first_name" => "Self Updated"
        }
      }

      conn = put(conn, "/#{organization.slug}/api/users/#{regular_user.id}", update_attrs)

      assert %{
               "data" => %{
                 "attributes" => attributes
               }
             } = json_response(conn, 200)

      assert attributes["first_name"] == "Self Updated"
    end

    test "requires appropriate Management API scopes", %{
      conn: conn,
      regular_user: regular_user,
      organization: organization
    } do
      # Set up connection without user scopes
      conn =
        conn
        |> assign(:current_scopes, ["profile:read"])

      update_attrs = %{
        "user" => %{
          "first_name" => "Updated",
          "last_name" => "Name"
        }
      }

      conn = put(conn, "/#{organization.slug}/api/users/#{regular_user.id}", update_attrs)

      assert %{
               "error" => %{
                 "type" => "insufficient_scope",
                 "message" => "Insufficient scope to access this resource"
               }
             } = json_response(conn, 403)
    end

    test "returns error for missing user parameters", %{
      conn: conn,
      regular_user: regular_user,
      organization: organization
    } do
      conn = put(conn, "/#{organization.slug}/api/users/#{regular_user.id}", %{})

      assert %{
               "error" => %{
                 "type" => "invalid_request",
                 "message" => "Request must include user parameters"
               }
             } = json_response(conn, 400)
    end
  end

  describe "DELETE /api/users/:id" do
    test "admin can delete users", %{
      conn: conn,
      regular_user: regular_user,
      organization: organization
    } do
      conn = delete(conn, "/#{organization.slug}/api/users/#{regular_user.id}")

      assert response(conn, 204)
    end

    test "admin cannot delete themselves", %{
      conn: conn,
      admin_user: admin_user,
      organization: organization
    } do
      conn = delete(conn, "/#{organization.slug}/api/users/#{admin_user.id}")

      assert %{
               "error" => %{
                 "type" => "invalid_operation",
                 "message" => "You cannot delete your own account"
               }
             } = json_response(conn, 403)
    end

    test "requires appropriate Management API scopes", %{
      conn: conn,
      regular_user: regular_user,
      organization: organization
    } do
      # Set up connection without user scopes
      conn =
        conn
        |> assign(:current_scopes, ["profile:read"])

      conn = delete(conn, "/#{organization.slug}/api/users/#{regular_user.id}")

      assert %{
               "error" => %{
                 "type" => "insufficient_scope",
                 "message" => "Insufficient scope to access this resource"
               }
             } = json_response(conn, 403)
    end
  end

  describe "PUT /api/users/:id/role" do
    test "admin can update user roles", %{
      conn: conn,
      regular_user: regular_user,
      organization: organization
    } do
      conn =
        put(conn, "/#{organization.slug}/api/users/#{regular_user.id}/role", %{"role" => "admin"})

      assert %{
               "data" => %{
                 "attributes" => _attributes
               }
             } = json_response(conn, 200)
    end

    test "returns error for invalid role", %{
      conn: conn,
      regular_user: regular_user,
      organization: organization
    } do
      conn =
        put(conn, "/#{organization.slug}/api/users/#{regular_user.id}/role", %{
          "role" => "invalid_role"
        })

      assert %{
               "error" => %{
                 "type" => "validation_failed"
               }
             } = json_response(conn, 422)
    end

    test "requires appropriate Management API scopes", %{
      conn: conn,
      regular_user: regular_user,
      organization: organization
    } do
      # Set up connection without user scopes
      conn =
        conn
        |> assign(:current_scopes, ["profile:read"])

      conn =
        put(conn, "/#{organization.slug}/api/users/#{regular_user.id}/role", %{"role" => "admin"})

      assert %{
               "error" => %{
                 "type" => "insufficient_scope",
                 "message" => "Insufficient scope to access this resource"
               }
             } = json_response(conn, 403)
    end

    test "returns error for missing role parameter", %{
      conn: conn,
      regular_user: regular_user,
      organization: organization
    } do
      conn = put(conn, "/#{organization.slug}/api/users/#{regular_user.id}/role", %{})

      assert %{
               "error" => %{
                 "type" => "invalid_request",
                 "message" => "Request must include role parameter"
               }
             } = json_response(conn, 400)
    end
  end

  describe "GET /api/users/:id/mfa" do
    test "returns MFA status for user without TOTP", %{
      conn: conn,
      regular_user: regular_user,
      organization: organization
    } do
      conn = get(conn, "/#{organization.slug}/api/users/#{regular_user.id}/mfa")

      assert %{
               "data" => %{
                 "id" => user_id,
                 "type" => "mfa_status",
                 "attributes" => %{
                   "totp_enabled" => false,
                   "totp_enabled_at" => nil,
                   "backup_codes_count" => 0,
                   "trusted_devices_count" => 0,
                   "lockout" => nil
                 }
               },
               "links" => %{"self" => _}
             } = json_response(conn, 200)

      assert user_id == regular_user.id
    end

    test "returns MFA status for user with TOTP enabled", %{
      conn: conn,
      regular_user: regular_user,
      organization: organization
    } do
      # Enable TOTP for user
      {:ok, secret} = Authify.MFA.setup_totp(regular_user)
      code = NimbleTOTP.verification_code(secret)
      {:ok, regular_user, _codes} = Authify.MFA.complete_totp_setup(regular_user, code, secret)

      conn = get(conn, "/#{organization.slug}/api/users/#{regular_user.id}/mfa")

      assert %{
               "data" => %{
                 "id" => user_id,
                 "type" => "mfa_status",
                 "attributes" => %{
                   "totp_enabled" => true,
                   "totp_enabled_at" => totp_enabled_at,
                   "backup_codes_count" => backup_codes_count,
                   "trusted_devices_count" => 0,
                   "lockout" => nil
                 }
               },
               "links" => %{"self" => _}
             } = json_response(conn, 200)

      assert user_id == regular_user.id
      refute is_nil(totp_enabled_at)
      assert backup_codes_count == 10
    end

    test "returns MFA status with lockout info when user is locked out", %{
      conn: conn,
      regular_user: regular_user,
      organization: organization
    } do
      # Enable TOTP for user
      {:ok, secret} = Authify.MFA.setup_totp(regular_user)
      code = NimbleTOTP.verification_code(secret)
      {:ok, regular_user, _codes} = Authify.MFA.complete_totp_setup(regular_user, code, secret)

      # Create lockout record directly
      locked_until =
        DateTime.utc_now() |> DateTime.add(300, :second) |> DateTime.truncate(:second)

      {:ok, _lockout} =
        Authify.Repo.insert(%Authify.MFA.TotpLockout{
          user_id: regular_user.id,
          locked_at: DateTime.utc_now() |> DateTime.truncate(:second),
          locked_until: locked_until,
          failed_attempts: 5
        })

      conn = get(conn, "/#{organization.slug}/api/users/#{regular_user.id}/mfa")

      assert %{
               "data" => %{
                 "attributes" => %{
                   "totp_enabled" => true,
                   "lockout" => %{
                     "locked" => true,
                     "locked_until" => _locked_until_str
                   }
                 }
               }
             } = json_response(conn, 200)
    end

    test "returns 404 when user not found in organization", %{
      conn: conn,
      organization: organization
    } do
      conn = get(conn, "/#{organization.slug}/api/users/99999/mfa")

      assert %{
               "error" => %{
                 "type" => "resource_not_found",
                 "message" => "User not found in organization"
               }
             } = json_response(conn, 404)
    end

    test "requires users:read scope", %{
      conn: conn,
      regular_user: regular_user,
      organization: organization
    } do
      conn =
        conn
        |> assign(:current_scopes, ["profile:read"])

      conn = get(conn, "/#{organization.slug}/api/users/#{regular_user.id}/mfa")

      assert %{
               "error" => %{
                 "type" => "insufficient_scope",
                 "message" => "Insufficient scope to access this resource"
               }
             } = json_response(conn, 403)
    end
  end

  describe "POST /api/users/:id/mfa/unlock" do
    test "unlocks user who is locked out", %{
      conn: conn,
      regular_user: regular_user,
      organization: organization
    } do
      # Enable TOTP for user
      {:ok, secret} = Authify.MFA.setup_totp(regular_user)
      code = NimbleTOTP.verification_code(secret)
      {:ok, regular_user, _codes} = Authify.MFA.complete_totp_setup(regular_user, code, secret)

      # Create lockout record directly
      locked_until =
        DateTime.utc_now() |> DateTime.add(300, :second) |> DateTime.truncate(:second)

      {:ok, _lockout} =
        Authify.Repo.insert(%Authify.MFA.TotpLockout{
          user_id: regular_user.id,
          locked_at: DateTime.utc_now() |> DateTime.truncate(:second),
          locked_until: locked_until,
          failed_attempts: 5
        })

      # Verify lockout exists
      assert {:error, {:locked, _}} = Authify.MFA.check_lockout(regular_user)

      # Unlock via API
      conn = post(conn, "/#{organization.slug}/api/users/#{regular_user.id}/mfa/unlock")

      assert %{
               "data" => %{
                 "id" => user_id,
                 "type" => "mfa_unlock",
                 "attributes" => %{
                   "message" => "User MFA lockout has been removed"
                 }
               },
               "links" => %{
                 "self" => _,
                 "user" => _
               }
             } = json_response(conn, 200)

      assert user_id == regular_user.id

      # Verify lockout removed
      regular_user = Authify.Repo.reload!(regular_user)
      assert {:ok, :no_lockout} = Authify.MFA.check_lockout(regular_user)
    end

    test "returns 404 when user not found in organization", %{
      conn: conn,
      organization: organization
    } do
      conn = post(conn, "/#{organization.slug}/api/users/99999/mfa/unlock")

      assert %{
               "error" => %{
                 "type" => "resource_not_found",
                 "message" => "User not found in organization"
               }
             } = json_response(conn, 404)
    end

    test "requires users:write scope", %{
      conn: conn,
      regular_user: regular_user,
      organization: organization
    } do
      conn =
        conn
        |> assign(:current_scopes, ["users:read"])

      conn = post(conn, "/#{organization.slug}/api/users/#{regular_user.id}/mfa/unlock")

      assert %{
               "error" => %{
                 "type" => "insufficient_scope",
                 "message" => "Insufficient scope to access this resource"
               }
             } = json_response(conn, 403)
    end
  end

  describe "POST /api/users/:id/mfa/reset" do
    test "resets user MFA completely", %{
      conn: conn,
      regular_user: regular_user,
      organization: organization
    } do
      # Enable TOTP for user
      {:ok, secret} = Authify.MFA.setup_totp(regular_user)
      code = NimbleTOTP.verification_code(secret)
      {:ok, regular_user, _codes} = Authify.MFA.complete_totp_setup(regular_user, code, secret)

      # Create trusted device
      {:ok, _device, _token} =
        Authify.MFA.create_trusted_device(regular_user, %{
          device_name: "Test Device",
          ip_address: "127.0.0.1",
          user_agent: "Test"
        })

      # Verify TOTP is enabled
      regular_user = Authify.Repo.reload!(regular_user)
      assert Authify.Accounts.User.totp_enabled?(regular_user)
      assert length(Authify.MFA.list_trusted_devices(regular_user)) == 1

      # Reset MFA via API
      conn = post(conn, "/#{organization.slug}/api/users/#{regular_user.id}/mfa/reset")

      assert %{
               "data" => %{
                 "id" => user_id,
                 "type" => "mfa_reset",
                 "attributes" => %{
                   "message" => "User MFA has been reset. They will need to set it up again."
                 }
               },
               "links" => %{
                 "self" => _,
                 "user" => _
               }
             } = json_response(conn, 200)

      assert user_id == regular_user.id

      # Verify MFA disabled and devices revoked
      regular_user = Authify.Repo.reload!(regular_user)
      refute Authify.Accounts.User.totp_enabled?(regular_user)
      assert Enum.empty?(Authify.MFA.list_trusted_devices(regular_user))
      assert Authify.MFA.backup_codes_count(regular_user) == 0
    end

    test "returns 404 when user not found in organization", %{
      conn: conn,
      organization: organization
    } do
      conn = post(conn, "/#{organization.slug}/api/users/99999/mfa/reset")

      assert %{
               "error" => %{
                 "type" => "resource_not_found",
                 "message" => "User not found in organization"
               }
             } = json_response(conn, 404)
    end

    test "requires users:write scope", %{
      conn: conn,
      regular_user: regular_user,
      organization: organization
    } do
      conn =
        conn
        |> assign(:current_scopes, ["users:read"])

      conn = post(conn, "/#{organization.slug}/api/users/#{regular_user.id}/mfa/reset")

      assert %{
               "error" => %{
                 "type" => "insufficient_scope",
                 "message" => "Insufficient scope to access this resource"
               }
             } = json_response(conn, 403)
    end
  end
end
