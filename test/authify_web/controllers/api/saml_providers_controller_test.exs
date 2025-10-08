defmodule AuthifyWeb.API.SAMLProvidersControllerTest do
  use AuthifyWeb.ConnCase
  import Authify.AccountsFixtures
  import Authify.SAMLFixtures

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
      |> assign(:current_scopes, ["saml:read", "saml:write"])

    %{conn: conn, admin_user: admin_user, organization: organization}
  end

  @valid_attrs %{
    name: "Test SAML Provider",
    entity_id: "https://sp.example.com",
    acs_url: "https://sp.example.com/saml/acs",
    sls_url: "https://sp.example.com/saml/sls",
    certificate:
      "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890\n-----END CERTIFICATE-----",
    metadata: "<?xml version=\"1.0\"?><EntityDescriptor>...</EntityDescriptor>",
    attribute_mapping:
      "{\"email\": \"email\", \"first_name\": \"first_name\", \"last_name\": \"last_name\"}",
    sign_requests: false,
    sign_assertions: true,
    encrypt_assertions: false,
    is_active: true
  }

  @invalid_attrs %{
    name: nil,
    entity_id: nil,
    acs_url: nil
  }

  describe "GET /api/saml-providers" do
    test "lists all SAML providers for organization", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      saml_provider = service_provider_fixture(organization: organization)

      conn =
        conn
        |> put_req_header("accept", "application/vnd.authify.v1+json")
        |> put_req_header(
          "authorization",
          "Bearer #{generate_valid_token(admin_user, organization)}"
        )
        |> get("/#{organization.slug}/api/saml-providers")

      assert %{
               "data" => [provider],
               "links" => %{
                 "first" => _,
                 "self" => _
               },
               "meta" => %{
                 "page" => 1,
                 "per_page" => 25,
                 "total" => 1
               }
             } = json_response(conn, 200)

      assert provider["id"] == to_string(saml_provider.id)
      assert provider["type"] == "service_provider"
      assert provider["attributes"]["name"] == saml_provider.name
      assert provider["attributes"]["entity_id"] == saml_provider.entity_id

      assert provider["links"]["self"] ==
               "/#{organization.slug}/api/saml-providers/#{saml_provider.id}"
    end

    test "returns empty list when no SAML providers exist", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      conn =
        conn
        |> put_req_header("accept", "application/vnd.authify.v1+json")
        |> put_req_header(
          "authorization",
          "Bearer #{generate_valid_token(admin_user, organization)}"
        )
        |> get("/#{organization.slug}/api/saml-providers")

      assert %{
               "data" => [],
               "meta" => %{"total" => 0}
             } = json_response(conn, 200)
    end

    test "supports pagination", %{conn: conn, organization: organization, admin_user: admin_user} do
      # Create multiple SAML providers
      for i <- 1..3 do
        service_provider_fixture(%{
          organization: organization,
          entity_id: "https://sp#{i}.example.com",
          name: "Provider #{i}"
        })
      end

      conn =
        conn
        |> put_req_header("accept", "application/vnd.authify.v1+json")
        |> put_req_header(
          "authorization",
          "Bearer #{generate_valid_token(admin_user, organization)}"
        )
        |> get("/#{organization.slug}/api/saml-providers?page=1&per_page=2")

      response = json_response(conn, 200)
      assert length(response["data"]) == 2
      assert response["meta"]["total"] == 3
      assert response["meta"]["page"] == 1
      assert response["meta"]["per_page"] == 2
      assert response["links"]["next"]
    end
  end

  describe "GET /api/saml-providers/:id" do
    test "shows SAML provider when it exists", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      saml_provider = service_provider_fixture(organization: organization)

      conn =
        conn
        |> put_req_header("accept", "application/vnd.authify.v1+json")
        |> put_req_header(
          "authorization",
          "Bearer #{generate_valid_token(admin_user, organization)}"
        )
        |> get("/#{organization.slug}/api/saml-providers/#{saml_provider.id}")

      assert %{
               "data" => %{
                 "id" => id,
                 "type" => "service_provider",
                 "attributes" => attributes,
                 "links" => %{"self" => _self_link}
               }
             } = json_response(conn, 200)

      assert id == to_string(saml_provider.id)
      assert attributes["name"] == saml_provider.name
      assert attributes["entity_id"] == saml_provider.entity_id
      assert attributes["acs_url"] == saml_provider.acs_url
    end

    test "returns 404 when SAML provider not found", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      conn =
        conn
        |> put_req_header("accept", "application/vnd.authify.v1+json")
        |> put_req_header(
          "authorization",
          "Bearer #{generate_valid_token(admin_user, organization)}"
        )
        |> get("/#{organization.slug}/api/saml-providers/999")

      assert %{
               "error" => %{
                 "type" => "resource_not_found",
                 "message" => "SAML provider not found in organization"
               }
             } = json_response(conn, 404)
    end
  end

  describe "POST /api/saml-providers" do
    test "creates SAML provider with valid data", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      conn =
        conn
        |> put_req_header("accept", "application/vnd.authify.v1+json")
        |> put_req_header(
          "authorization",
          "Bearer #{generate_valid_token(admin_user, organization)}"
        )
        |> put_req_header("content-type", "application/vnd.authify.v1+json")
        |> post("/#{organization.slug}/api/saml-providers", %{"saml_provider" => @valid_attrs})

      assert %{
               "data" => %{
                 "id" => id,
                 "type" => "service_provider",
                 "attributes" => attributes,
                 "links" => %{"self" => _self_link}
               }
             } = json_response(conn, 201)

      assert is_binary(id)
      assert attributes["name"] == @valid_attrs.name
      assert attributes["entity_id"] == @valid_attrs.entity_id
      assert attributes["acs_url"] == @valid_attrs.acs_url
    end

    test "returns validation errors with invalid data", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      conn =
        conn
        |> put_req_header("accept", "application/vnd.authify.v1+json")
        |> put_req_header(
          "authorization",
          "Bearer #{generate_valid_token(admin_user, organization)}"
        )
        |> put_req_header("content-type", "application/vnd.authify.v1+json")
        |> post("/#{organization.slug}/api/saml-providers", %{"saml_provider" => @invalid_attrs})

      assert %{
               "error" => %{
                 "type" => "validation_failed",
                 "message" => "The request data failed validation",
                 "details" => details
               }
             } = json_response(conn, 422)

      assert details["name"]
      assert details["entity_id"]
      assert details["acs_url"]
    end
  end

  describe "PUT /api/saml-providers/:id" do
    test "updates SAML provider with valid data", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      saml_provider = service_provider_fixture(organization: organization)

      update_attrs = %{
        name: "Updated SAML Provider",
        entity_id: "https://updated-sp.example.com"
      }

      conn =
        conn
        |> put_req_header("accept", "application/vnd.authify.v1+json")
        |> put_req_header(
          "authorization",
          "Bearer #{generate_valid_token(admin_user, organization)}"
        )
        |> put_req_header("content-type", "application/vnd.authify.v1+json")
        |> put("/#{organization.slug}/api/saml-providers/#{saml_provider.id}", %{
          "saml_provider" => update_attrs
        })

      assert %{
               "data" => %{
                 "attributes" => attributes
               }
             } = json_response(conn, 200)

      assert attributes["name"] == update_attrs.name
      assert attributes["entity_id"] == update_attrs.entity_id
    end

    test "returns 404 when SAML provider not found", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      conn =
        conn
        |> put_req_header("accept", "application/vnd.authify.v1+json")
        |> put_req_header(
          "authorization",
          "Bearer #{generate_valid_token(admin_user, organization)}"
        )
        |> put_req_header("content-type", "application/vnd.authify.v1+json")
        |> put("/#{organization.slug}/api/saml-providers/999", %{
          "saml_provider" => %{"name" => "Updated"}
        })

      assert %{
               "error" => %{
                 "type" => "resource_not_found"
               }
             } = json_response(conn, 404)
    end
  end

  describe "DELETE /api/saml-providers/:id" do
    test "deletes SAML provider", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      saml_provider = service_provider_fixture(organization: organization)

      conn =
        conn
        |> put_req_header("accept", "application/vnd.authify.v1+json")
        |> put_req_header(
          "authorization",
          "Bearer #{generate_valid_token(admin_user, organization)}"
        )
        |> delete("/#{organization.slug}/api/saml-providers/#{saml_provider.id}")

      assert response(conn, 204)

      # Verify it's deleted
      assert_raise Ecto.NoResultsError, fn ->
        Authify.SAML.get_service_provider!(saml_provider.id, organization)
      end
    end

    test "returns 404 when SAML provider not found", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      conn =
        conn
        |> put_req_header("accept", "application/vnd.authify.v1+json")
        |> put_req_header(
          "authorization",
          "Bearer #{generate_valid_token(admin_user, organization)}"
        )
        |> delete("/#{organization.slug}/api/saml-providers/999")

      assert %{
               "error" => %{
                 "type" => "resource_not_found"
               }
             } = json_response(conn, 404)
    end
  end

  defp generate_valid_token(admin_user, organization) do
    {:ok, token, _claims} = Authify.Guardian.encode_and_sign(admin_user, %{org: organization.id})
    token
  end
end
