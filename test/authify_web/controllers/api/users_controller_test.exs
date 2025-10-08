defmodule AuthifyWeb.API.UsersControllerTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

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
      assert attributes["email"] == regular_user.email
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
          "email" => "newuser@example.com",
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

      assert attributes["email"] == "newuser@example.com"
      assert attributes["first_name"] == "New"
      assert attributes["last_name"] == "User"
    end

    test "returns validation errors for invalid email", %{conn: conn, organization: organization} do
      invalid_attrs = %{
        "user" => %{
          "email" => "invalid-email",
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

      assert details["email"]
      # Note: password validation only runs when email is valid
    end

    test "returns validation errors for invalid password", %{
      conn: conn,
      organization: organization
    } do
      invalid_attrs = %{
        "user" => %{
          "email" => "valid@example.com",
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
          "email" => "newuser@example.com",
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
end
