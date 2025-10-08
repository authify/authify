defmodule AuthifyWeb.API.OAuthIntegrationTest do
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures
  import Authify.OAuthFixtures
  import Authify.SAMLFixtures

  describe "OAuth access token authentication for Management API" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      application = management_api_application_fixture(organization: organization)

      %{
        organization: organization,
        user: user,
        application: application
      }
    end

    test "can access SAML providers API with OAuth access token", %{
      conn: conn,
      application: application,
      organization: organization
    } do
      # First, get an OAuth access token via client credentials
      params = %{
        "grant_type" => "client_credentials",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret,
        "scope" => "management_app:read saml:read"
      }

      token_conn = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      token_response = json_response(token_conn, 200)
      access_token = token_response["access_token"]

      # Create a SAML provider to test against
      service_provider = service_provider_fixture(organization: organization)

      # Now use the OAuth access token to access the Management API
      api_conn =
        conn
        |> put_req_header("authorization", "Bearer #{access_token}")
        |> put_req_header("accept", "application/vnd.authify.v1+json")

      # Test GET /api/saml-providers
      response = get(api_conn, ~p"/#{organization.slug}/api/saml-providers")
      assert response.status == 200

      response_data = json_response(response, 200)
      assert response_data["data"]
      assert length(response_data["data"]) == 1
      assert hd(response_data["data"])["id"] == to_string(service_provider.id)
    end

    test "can create SAML provider with OAuth access token", %{
      conn: conn,
      application: application,
      organization: organization
    } do
      # Get OAuth access token with write permissions
      params = %{
        "grant_type" => "client_credentials",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret,
        "scope" => "management_app:write saml:write"
      }

      token_conn = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      token_response = json_response(token_conn, 200)
      access_token = token_response["access_token"]

      # Use the OAuth access token to create a SAML provider
      api_conn =
        conn
        |> put_req_header("authorization", "Bearer #{access_token}")
        |> put_req_header("accept", "application/vnd.authify.v1+json")
        |> put_req_header("content-type", "application/json")

      saml_data = %{
        "saml_provider" => %{
          "name" => "Test SAML Provider",
          "entity_id" => "https://example.com/saml/metadata",
          "acs_url" => "https://example.com/saml/acs",
          "sls_url" => "https://example.com/saml/sls",
          "certificate" =>
            "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890\n-----END CERTIFICATE-----",
          "attribute_mapping" =>
            "{\"email\": \"email\", \"first_name\": \"first_name\", \"last_name\": \"last_name\"}",
          "metadata" => "<?xml version=\"1.0\"?><EntityDescriptor>...</EntityDescriptor>",
          "sign_requests" => false,
          "sign_assertions" => true,
          "encrypt_assertions" => false,
          "is_active" => true
        }
      }

      response = post(api_conn, ~p"/#{organization.slug}/api/saml-providers", saml_data)
      assert response.status == 201

      response_data = json_response(response, 201)
      assert response_data["data"]["attributes"]["name"] == "Test SAML Provider"
    end

    test "returns error for invalid OAuth access token", %{conn: conn, organization: organization} do
      # Use an invalid OAuth access token
      api_conn =
        conn
        |> put_req_header("authorization", "Bearer invalid_token")
        |> put_req_header("accept", "application/vnd.authify.v1+json")

      response = get(api_conn, ~p"/#{organization.slug}/api/saml-providers")
      assert response.status == 401

      response_data = json_response(response, 401)
      assert response_data["error"]["type"] == "authentication_required"
    end

    test "returns error for expired OAuth access token", %{
      conn: conn,
      application: application,
      organization: organization
    } do
      # Create an expired access token manually
      {:ok, expired_token} =
        Authify.OAuth.create_management_api_access_token(application, "management_app:read")

      # Update the token to be expired
      Authify.Repo.update!(
        Ecto.Changeset.change(expired_token,
          expires_at: DateTime.truncate(DateTime.add(DateTime.utc_now(), -3600), :second)
        )
      )

      # Try to use the expired token
      api_conn =
        conn
        |> put_req_header("authorization", "Bearer #{expired_token.token}")
        |> put_req_header("accept", "application/vnd.authify.v1+json")

      response = get(api_conn, ~p"/#{organization.slug}/api/saml-providers")
      assert response.status == 401

      response_data = json_response(response, 401)
      assert response_data["error"]["type"] == "authentication_required"
    end
  end
end
