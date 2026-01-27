defmodule AuthifyWeb.API.InvitationsControllerTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  setup %{conn: conn} do
    organization = organization_fixture()
    admin_user = user_fixture(organization: organization, role: "admin")
    regular_user = user_fixture(organization: organization, role: "user")

    # Create some test invitations
    {:ok, invitation1} =
      Authify.Accounts.create_invitation(%{
        "email" => "pending@example.com",
        "role" => "user",
        "organization_id" => organization.id,
        "invited_by_id" => admin_user.id
      })

    {:ok, invitation2} =
      Authify.Accounts.create_invitation(%{
        "email" => "admin-invite@example.com",
        "role" => "admin",
        "organization_id" => organization.id,
        "invited_by_id" => admin_user.id
      })

    # Accept one invitation to test filtering
    {:ok, _accepted_invitation} =
      Authify.Accounts.update_invitation(invitation2, %{
        "accepted_at" => DateTime.utc_now()
      })

    # Set up API headers and authentication as admin
    conn =
      conn
      |> put_req_header("accept", "application/vnd.authify.v1+json")
      |> put_req_header("content-type", "application/vnd.authify.v1+json")
      |> log_in_user(admin_user)
      |> assign(:current_user, admin_user)
      |> assign(:current_organization, organization)
      |> assign(:api_authenticated, true)
      |> assign(:current_scopes, ["invitations:read", "invitations:write"])

    %{
      conn: conn,
      admin_user: admin_user,
      regular_user: regular_user,
      organization: organization,
      invitation1: invitation1,
      invitation2: invitation2
    }
  end

  describe "GET /api/invitations" do
    @describetag :capture_log
    test "returns paginated list of invitations with HATEOAS", %{
      conn: conn,
      organization: organization
    } do
      conn = get(conn, "/#{organization.slug}/api/invitations")

      assert %{
               "data" => invitations,
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

      assert self_link == "http://localhost:4002/#{organization.slug}/api/invitations"

      assert length(invitations) == 2
      assert String.contains?(first_link, "page=1&per_page=25")

      # Check invitation structure
      invitation_data = List.first(invitations)

      assert %{
               "id" => _,
               "type" => "invitation",
               "attributes" => attributes,
               "links" => %{"self" => self_link}
             } = invitation_data

      assert String.starts_with?(self_link, "/#{organization.slug}/api/invitations/")

      # Verify token is excluded for security
      refute Map.has_key?(attributes, "token")

      # Verify expected attributes are present
      assert Map.has_key?(attributes, "email")
      assert Map.has_key?(attributes, "role")
      assert Map.has_key?(attributes, "expires_at")
      assert Map.has_key?(attributes, "accepted_at")
    end

    test "supports pagination parameters", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/api/invitations?page=1&per_page=1")

      assert %{
               "data" => invitations,
               "meta" => %{
                 "total" => 2,
                 "page" => 1,
                 "per_page" => 1
               }
             } = json_response(conn, 200)

      assert length(invitations) == 1
    end

    test "supports status filtering - pending", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/api/invitations?status=pending")

      assert %{
               "data" => invitations,
               "meta" => %{
                 "total" => 1
               }
             } = json_response(conn, 200)

      assert length(invitations) == 1

      invitation_data = List.first(invitations)
      assert invitation_data["attributes"]["accepted_at"] == nil
    end

    test "supports status filtering - accepted", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/api/invitations?status=accepted")

      assert %{
               "data" => invitations,
               "meta" => %{
                 "total" => 1
               }
             } = json_response(conn, 200)

      assert length(invitations) == 1

      invitation_data = List.first(invitations)
      assert invitation_data["attributes"]["accepted_at"] != nil
    end

    test "requires appropriate Management API scopes", %{conn: conn, organization: organization} do
      # Set up connection without invitation scopes
      conn =
        conn
        |> assign(:current_scopes, ["profile:read"])

      conn = get(conn, "/#{organization.slug}/api/invitations")

      assert %{
               "error" => %{
                 "type" => "insufficient_scope",
                 "message" => "Insufficient scope to access this resource"
               }
             } = json_response(conn, 403)
    end
  end

  describe "GET /api/invitations/:id" do
    @describetag :capture_log
    test "returns invitation details", %{
      conn: conn,
      invitation1: invitation,
      organization: organization
    } do
      conn = get(conn, "/#{organization.slug}/api/invitations/#{invitation.id}")

      assert %{
               "data" => %{
                 "id" => id,
                 "type" => "invitation",
                 "attributes" => attributes,
                 "links" => %{"self" => self_link}
               }
             } = json_response(conn, 200)

      assert id == to_string(invitation.id)
      assert attributes["email"] == invitation.email
      assert attributes["role"] == invitation.role
      refute Map.has_key?(attributes, "token")
      assert String.starts_with?(self_link, "/#{organization.slug}/api/invitations/")
    end

    test "returns 404 for non-existent invitation", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/api/invitations/99999")

      assert %{
               "error" => %{
                 "type" => "resource_not_found",
                 "message" => "Invitation not found in organization"
               }
             } = json_response(conn, 404)
    end

    test "requires appropriate Management API scopes", %{
      conn: conn,
      invitation1: invitation,
      organization: organization
    } do
      # Set up connection without invitation scopes
      conn =
        conn
        |> assign(:current_scopes, ["profile:read"])

      conn = get(conn, "/#{organization.slug}/api/invitations/#{invitation.id}")

      assert %{
               "error" => %{
                 "type" => "insufficient_scope",
                 "message" => "Insufficient scope to access this resource"
               }
             } = json_response(conn, 403)
    end
  end

  describe "POST /api/invitations" do
    @describetag :capture_log
    test "creates invitation with valid data", %{conn: conn, organization: organization} do
      invitation_attrs = %{
        "invitation" => %{
          "email" => "newuser@example.com",
          "role" => "user"
        }
      }

      conn = post(conn, "/#{organization.slug}/api/invitations", invitation_attrs)

      assert %{
               "data" => %{
                 "type" => "invitation",
                 "attributes" => attributes
               }
             } = json_response(conn, 201)

      assert attributes["email"] == "newuser@example.com"
      assert attributes["role"] == "user"
      refute Map.has_key?(attributes, "token")
    end

    test "creates admin invitation", %{conn: conn, organization: organization} do
      invitation_attrs = %{
        "invitation" => %{
          "email" => "newadmin@example.com",
          "role" => "admin"
        }
      }

      conn = post(conn, "/#{organization.slug}/api/invitations", invitation_attrs)

      assert %{
               "data" => %{
                 "attributes" => attributes
               }
             } = json_response(conn, 201)

      assert attributes["email"] == "newadmin@example.com"
      assert attributes["role"] == "admin"
    end

    test "returns validation errors for invalid email", %{conn: conn, organization: organization} do
      invalid_attrs = %{
        "invitation" => %{
          "email" => "invalid-email",
          "role" => "user"
        }
      }

      conn = post(conn, "/#{organization.slug}/api/invitations", invalid_attrs)

      assert %{
               "error" => %{
                 "type" => "validation_failed",
                 "details" => details
               }
             } = json_response(conn, 422)

      assert details["email"]
    end

    test "returns validation errors for invalid role", %{conn: conn, organization: organization} do
      invalid_attrs = %{
        "invitation" => %{
          "email" => "valid@example.com",
          "role" => "invalid_role"
        }
      }

      conn = post(conn, "/#{organization.slug}/api/invitations", invalid_attrs)

      assert %{
               "error" => %{
                 "type" => "validation_failed",
                 "details" => details
               }
             } = json_response(conn, 422)

      assert details["role"]
    end

    test "prevents duplicate invitations", %{
      conn: conn,
      invitation1: existing_invitation,
      organization: organization
    } do
      duplicate_attrs = %{
        "invitation" => %{
          "email" => existing_invitation.email,
          "role" => "user"
        }
      }

      conn = post(conn, "/#{organization.slug}/api/invitations", duplicate_attrs)

      assert %{
               "error" => %{
                 "type" => "validation_failed",
                 "details" => details
               }
             } = json_response(conn, 422)

      assert details["email"]
    end

    test "requires appropriate Management API scopes", %{conn: conn, organization: organization} do
      # Set up connection without invitation scopes
      conn =
        conn
        |> assign(:current_scopes, ["profile:read"])

      invitation_attrs = %{
        "invitation" => %{
          "email" => "test@example.com",
          "role" => "user"
        }
      }

      conn = post(conn, "/#{organization.slug}/api/invitations", invitation_attrs)

      assert %{
               "error" => %{
                 "type" => "insufficient_scope",
                 "message" => "Insufficient scope to access this resource"
               }
             } = json_response(conn, 403)
    end

    test "returns error for missing invitation parameters", %{
      conn: conn,
      organization: organization
    } do
      conn = post(conn, "/#{organization.slug}/api/invitations", %{})

      assert %{
               "error" => %{
                 "type" => "invalid_request",
                 "message" => "Request must include invitation parameters"
               }
             } = json_response(conn, 400)
    end
  end

  describe "PUT /api/invitations/:id" do
    @describetag :capture_log
    test "updates invitation with valid data", %{
      conn: conn,
      invitation1: invitation,
      organization: organization
    } do
      update_attrs = %{
        "invitation" => %{
          "role" => "admin"
        }
      }

      conn = put(conn, "/#{organization.slug}/api/invitations/#{invitation.id}", update_attrs)

      assert %{
               "data" => %{
                 "attributes" => attributes
               }
             } = json_response(conn, 200)

      assert attributes["role"] == "admin"
    end

    test "returns validation errors for invalid data", %{
      conn: conn,
      invitation1: invitation,
      organization: organization
    } do
      invalid_attrs = %{
        "invitation" => %{
          "role" => "invalid_role"
        }
      }

      conn = put(conn, "/#{organization.slug}/api/invitations/#{invitation.id}", invalid_attrs)

      assert %{
               "error" => %{
                 "type" => "validation_failed",
                 "details" => details
               }
             } = json_response(conn, 422)

      assert details["role"]
    end

    test "returns 404 for non-existent invitation", %{conn: conn, organization: organization} do
      conn =
        put(conn, "/#{organization.slug}/api/invitations/99999", %{
          "invitation" => %{"role" => "admin"}
        })

      assert %{
               "error" => %{
                 "type" => "resource_not_found"
               }
             } = json_response(conn, 404)
    end

    test "requires appropriate Management API scopes", %{
      conn: conn,
      invitation1: invitation,
      organization: organization
    } do
      # Set up connection without invitation scopes
      conn =
        conn
        |> assign(:current_scopes, ["profile:read"])

      update_attrs = %{
        "invitation" => %{
          "role" => "admin"
        }
      }

      conn = put(conn, "/#{organization.slug}/api/invitations/#{invitation.id}", update_attrs)

      assert %{
               "error" => %{
                 "type" => "insufficient_scope",
                 "message" => "Insufficient scope to access this resource"
               }
             } = json_response(conn, 403)
    end

    test "returns error for missing invitation parameters", %{
      conn: conn,
      invitation1: invitation,
      organization: organization
    } do
      conn = put(conn, "/#{organization.slug}/api/invitations/#{invitation.id}", %{})

      assert %{
               "error" => %{
                 "type" => "invalid_request",
                 "message" => "Request must include invitation parameters"
               }
             } = json_response(conn, 400)
    end
  end

  describe "DELETE /api/invitations/:id" do
    @describetag :capture_log
    test "deletes invitation", %{conn: conn, invitation1: invitation, organization: organization} do
      conn = delete(conn, "/#{organization.slug}/api/invitations/#{invitation.id}")

      assert response(conn, 204)
    end

    test "returns 404 for non-existent invitation", %{conn: conn, organization: organization} do
      conn = delete(conn, "/#{organization.slug}/api/invitations/99999")

      assert %{
               "error" => %{
                 "type" => "resource_not_found"
               }
             } = json_response(conn, 404)
    end

    test "requires appropriate Management API scopes", %{
      conn: conn,
      invitation1: invitation,
      organization: organization
    } do
      # Set up connection without invitation scopes
      conn =
        conn
        |> assign(:current_scopes, ["profile:read"])

      conn = delete(conn, "/#{organization.slug}/api/invitations/#{invitation.id}")

      assert %{
               "error" => %{
                 "type" => "insufficient_scope",
                 "message" => "Insufficient scope to access this resource"
               }
             } = json_response(conn, 403)
    end
  end
end
