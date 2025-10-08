defmodule AuthifyWeb.API.ApplicationsControllerTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures
  import Authify.OAuthFixtures

  setup %{conn: conn} do
    organization = organization_fixture()
    admin_user = user_fixture(organization: organization, role: "admin")

    # Set up API headers and authentication as admin
    conn =
      conn
      |> put_req_header("accept", "application/vnd.authify.v1+json")
      |> put_req_header("content-type", "application/vnd.authify.v1+json")
      |> log_in_user(admin_user)
      |> assign(:current_user, admin_user)
      |> assign(:current_organization, organization)
      |> assign(:api_authenticated, true)
      |> assign(:current_scopes, ["applications:read", "applications:write"])

    %{conn: conn, admin_user: admin_user, organization: organization}
  end

  describe "GET /api/applications" do
    test "returns paginated list of applications with HATEOAS", %{
      conn: conn,
      organization: organization
    } do
      _application1 = application_fixture(organization: organization)
      _application2 = application_fixture(organization: organization)

      conn = get(conn, "/#{organization.slug}/api/applications")

      assert %{
               "data" => applications,
               "links" => %{
                 "self" => _self_link,
                 "first" => _first_link
               },
               "meta" => %{
                 "total" => 2,
                 "page" => 1,
                 "per_page" => 25
               }
             } = json_response(conn, 200)

      assert length(applications) == 2

      # Check application structure
      app_data = List.first(applications)

      assert %{
               "id" => _,
               "type" => "application",
               "attributes" => attributes,
               "links" => %{"self" => _self_link}
             } = app_data

      # Ensure client_secret is not exposed
      refute Map.has_key?(attributes, "client_secret")
      assert Map.has_key?(attributes, "client_id")
      assert Map.has_key?(attributes, "name")
    end

    test "supports pagination parameters", %{conn: conn, organization: organization} do
      application_fixture(organization: organization)
      application_fixture(organization: organization)

      conn = get(conn, "/#{organization.slug}/api/applications?page=1&per_page=1")

      assert %{
               "data" => applications,
               "meta" => %{
                 "total" => 2,
                 "page" => 1,
                 "per_page" => 1
               }
             } = json_response(conn, 200)

      assert length(applications) == 1
    end

    test "requires appropriate Management API scopes", %{conn: conn, organization: organization} do
      application_fixture(organization: organization)

      # Set up connection without application scopes
      conn =
        conn
        |> assign(:current_scopes, ["profile:read"])

      conn = get(conn, "/#{organization.slug}/api/applications")

      response = json_response(conn, 403)
      assert response["error"]["type"] == "insufficient_scope"
    end
  end

  describe "GET /api/applications/:id" do
    test "returns application details", %{conn: conn, organization: organization} do
      application = application_fixture(organization: organization)

      conn = get(conn, "/#{organization.slug}/api/applications/#{application.id}")

      assert %{
               "data" => %{
                 "id" => id,
                 "type" => "application",
                 "attributes" => attributes,
                 "links" => %{"self" => _self_link}
               }
             } = json_response(conn, 200)

      assert id == to_string(application.id)
      assert attributes["name"] == application.name
      assert attributes["client_id"] == application.client_id
      refute Map.has_key?(attributes, "client_secret")
    end

    test "returns 404 for non-existent application", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/api/applications/99999")

      assert %{
               "error" => %{
                 "type" => "resource_not_found",
                 "message" => "Application not found in organization"
               }
             } = json_response(conn, 404)
    end

    test "requires appropriate Management API scopes", %{conn: conn, organization: organization} do
      application = application_fixture(organization: organization)

      # Set up connection without application scopes
      conn =
        conn
        |> assign(:current_scopes, ["profile:read"])

      conn = get(conn, "/#{organization.slug}/api/applications/#{application.id}")

      response = json_response(conn, 403)
      assert response["error"]["type"] == "insufficient_scope"
    end
  end

  describe "POST /api/applications" do
    test "creates application with valid data", %{conn: conn, organization: organization} do
      application_attrs = %{
        "application" => %{
          "name" => "Test App",
          "description" => "A test application",
          "redirect_uris" => "https://example.com/callback",
          "scopes" => "openid profile email"
        }
      }

      conn = post(conn, "/#{organization.slug}/api/applications", application_attrs)

      assert %{
               "data" => %{
                 "type" => "application",
                 "attributes" => attributes
               }
             } = json_response(conn, 201)

      assert attributes["name"] == "Test App"
      assert attributes["description"] == "A test application"
      assert Map.has_key?(attributes, "client_id")
      assert Map.has_key?(attributes, "client_secret")
      assert String.length(attributes["client_secret"]) > 0
    end

    test "returns validation errors for invalid data", %{conn: conn, organization: organization} do
      invalid_attrs = %{
        "application" => %{
          "name" => "",
          "redirect_uris" => "invalid-uri"
        }
      }

      conn = post(conn, "/#{organization.slug}/api/applications", invalid_attrs)

      assert %{
               "error" => %{
                 "type" => "validation_failed",
                 "details" => details
               }
             } = json_response(conn, 422)

      assert details["name"]
      assert details["redirect_uris"]
    end

    test "requires appropriate Management API scopes", %{conn: conn, organization: organization} do
      # Set up connection without application scopes
      conn =
        conn
        |> assign(:current_scopes, ["profile:read"])

      application_attrs = %{
        "application" => %{
          "name" => "Test App",
          "description" => "A test application",
          "redirect_uris" => "https://example.com/callback",
          "scopes" => "openid profile email"
        }
      }

      conn = post(conn, "/#{organization.slug}/api/applications", application_attrs)

      response = json_response(conn, 403)
      assert response["error"]["type"] == "insufficient_scope"
    end
  end

  describe "PUT /api/applications/:id" do
    test "updates application with valid data", %{conn: conn, organization: organization} do
      application = application_fixture(organization: organization)

      update_attrs = %{
        "application" => %{
          "name" => "Updated App",
          "description" => "Updated description"
        }
      }

      conn = put(conn, "/#{organization.slug}/api/applications/#{application.id}", update_attrs)

      assert %{
               "data" => %{
                 "attributes" => attributes
               }
             } = json_response(conn, 200)

      assert attributes["name"] == "Updated App"
      assert attributes["description"] == "Updated description"
    end

    test "returns 404 for non-existent application", %{conn: conn, organization: organization} do
      update_attrs = %{
        "application" => %{
          "name" => "Updated App"
        }
      }

      conn = put(conn, "/#{organization.slug}/api/applications/99999", update_attrs)

      assert %{
               "error" => %{
                 "type" => "resource_not_found",
                 "message" => "Application not found in organization"
               }
             } = json_response(conn, 404)
    end

    test "requires appropriate Management API scopes", %{conn: conn, organization: organization} do
      application = application_fixture(organization: organization)

      # Set up connection without application scopes
      conn =
        conn
        |> assign(:current_scopes, ["profile:read"])

      update_attrs = %{
        "application" => %{
          "name" => "Updated App",
          "description" => "Updated description"
        }
      }

      conn = put(conn, "/#{organization.slug}/api/applications/#{application.id}", update_attrs)

      response = json_response(conn, 403)
      assert response["error"]["type"] == "insufficient_scope"
    end
  end

  describe "DELETE /api/applications/:id" do
    test "deletes application", %{conn: conn, organization: organization} do
      application = application_fixture(organization: organization)

      conn = delete(conn, "/#{organization.slug}/api/applications/#{application.id}")

      assert response(conn, 204)
    end

    test "returns 404 for non-existent application", %{conn: conn, organization: organization} do
      conn = delete(conn, "/#{organization.slug}/api/applications/99999")

      assert %{
               "error" => %{
                 "type" => "resource_not_found",
                 "message" => "Application not found in organization"
               }
             } = json_response(conn, 404)
    end

    test "requires appropriate Management API scopes", %{conn: conn, organization: organization} do
      application = application_fixture(organization: organization)

      # Set up connection without application scopes
      conn =
        conn
        |> assign(:current_scopes, ["profile:read"])

      conn = delete(conn, "/#{organization.slug}/api/applications/#{application.id}")

      response = json_response(conn, 403)
      assert response["error"]["type"] == "insufficient_scope"
    end
  end

  describe "POST /api/applications/:application_id/regenerate-secret" do
    test "regenerates client secret", %{conn: conn, organization: organization} do
      application = application_fixture(organization: organization)
      original_secret = application.client_secret

      conn =
        post(conn, "/#{organization.slug}/api/applications/#{application.id}/regenerate-secret")

      assert %{
               "data" => %{
                 "attributes" => attributes
               }
             } = json_response(conn, 200)

      # The new secret should be returned in the response
      assert Map.has_key?(attributes, "client_secret")
      new_secret = attributes["client_secret"]
      assert new_secret != original_secret
      assert String.length(new_secret) > 0
    end

    test "returns 404 for non-existent application", %{conn: conn, organization: organization} do
      conn = post(conn, "/#{organization.slug}/api/applications/99999/regenerate-secret")

      assert %{
               "error" => %{
                 "type" => "resource_not_found",
                 "message" => "Application not found in organization"
               }
             } = json_response(conn, 404)
    end

    test "requires appropriate Management API scopes", %{conn: conn, organization: organization} do
      # Create a management API app
      mgmt_app = management_api_application_fixture(organization: organization)

      # Set up connection with only oauth app scopes (not management_app scopes)
      conn =
        conn
        |> assign(:current_scopes, ["applications:read"])

      conn = post(conn, "/#{organization.slug}/api/applications/#{mgmt_app.id}/regenerate-secret")

      response = json_response(conn, 403)
      assert response["error"]["type"] == "insufficient_scope"
    end
  end
end
