defmodule AuthifyWeb.API.ApplicationsControllerAuditTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures
  import Authify.OAuthFixtures

  alias Authify.AuditLog

  describe "Management API audit logging with client credentials (service account)" do
    setup do
      organization = organization_fixture()
      application = management_api_application_fixture(organization: organization)

      %{
        organization: organization,
        application: application
      }
    end

    test "logs oauth_client_created event with application actor when using client credentials",
         %{conn: conn, organization: organization, application: application} do
      # Get OAuth access token with client credentials
      params = %{
        "grant_type" => "client_credentials",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret,
        "scope" => "applications:write"
      }

      token_conn = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      token_response = json_response(token_conn, 200)
      access_token = token_response["access_token"]

      # Use the OAuth access token to create an application via API
      api_conn =
        conn
        |> put_req_header("authorization", "Bearer #{access_token}")
        |> put_req_header("accept", "application/json")
        |> put_req_header("content-type", "application/json")

      app_params = %{
        "application" => %{
          "name" => "Created By Service Account",
          "application_type" => "oauth2_app",
          "grant_types" => "authorization_code",
          "redirect_uris" => "http://localhost:3000/callback",
          "scopes" => "openid profile"
        }
      }

      response = post(api_conn, ~p"/#{organization.slug}/api/applications", app_params)
      assert %{"data" => data} = json_response(response, 201)
      app_id = String.to_integer(data["id"])

      # Give async task time to complete
      Process.sleep(100)

      events =
        AuditLog.list_events(organization_id: organization.id, event_type: "oauth_client_created")

      assert length(events) == 1

      event = hd(events)
      # THIS IS THE KEY TEST: actor should be "application", not "user"
      assert event.actor_type == "application"
      assert event.actor_id == application.id
      assert event.actor_name == application.name
      assert event.resource_type == "oauth_application"
      assert event.resource_id == app_id
      assert event.outcome == "success"
      assert event.metadata["name"] == "Created By Service Account"
    end

    test "logs oauth_client_updated event with application actor when using client credentials",
         %{conn: conn, organization: organization, application: application} do
      # Create an application to update
      app = application_fixture(%{organization_id: organization.id})

      # Get OAuth access token
      params = %{
        "grant_type" => "client_credentials",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret,
        "scope" => "applications:write"
      }

      token_conn = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      token_response = json_response(token_conn, 200)
      access_token = token_response["access_token"]

      # Update the application via API
      api_conn =
        conn
        |> put_req_header("authorization", "Bearer #{access_token}")
        |> put_req_header("accept", "application/json")
        |> put_req_header("content-type", "application/json")

      update_params = %{
        "application" => %{
          "name" => "Updated By Service"
        }
      }

      response =
        put(api_conn, ~p"/#{organization.slug}/api/applications/#{app.id}", update_params)

      assert json_response(response, 200)

      # Give async task time to complete
      Process.sleep(100)

      events =
        AuditLog.list_events(organization_id: organization.id, event_type: "oauth_client_updated")

      assert length(events) == 1

      event = hd(events)
      assert event.actor_type == "application"
      assert event.actor_id == application.id
      assert event.actor_name == application.name
      assert event.resource_type == "oauth_application"
      assert event.resource_id == app.id
      assert event.outcome == "success"
    end

    test "logs oauth_client_deleted event with application actor when using client credentials",
         %{conn: conn, organization: organization, application: application} do
      # Create an application to delete
      app = application_fixture(%{organization_id: organization.id})

      # Get OAuth access token
      params = %{
        "grant_type" => "client_credentials",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret,
        "scope" => "applications:write"
      }

      token_conn = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      token_response = json_response(token_conn, 200)
      access_token = token_response["access_token"]

      # Delete the application via API
      api_conn =
        conn
        |> put_req_header("authorization", "Bearer #{access_token}")
        |> put_req_header("accept", "application/json")

      response = delete(api_conn, ~p"/#{organization.slug}/api/applications/#{app.id}")
      assert response(response, 204)

      # Give async task time to complete
      Process.sleep(100)

      events =
        AuditLog.list_events(organization_id: organization.id, event_type: "oauth_client_deleted")

      assert length(events) == 1

      event = hd(events)
      assert event.actor_type == "application"
      assert event.actor_id == application.id
      assert event.actor_name == application.name
      assert event.resource_type == "oauth_application"
      assert event.resource_id == app.id
      assert event.outcome == "success"
    end

    test "logs oauth_client_secret_regenerated event with application actor", %{
      conn: conn,
      organization: organization,
      application: application
    } do
      # Create an application
      app = application_fixture(%{organization_id: organization.id})

      # Get OAuth access token
      params = %{
        "grant_type" => "client_credentials",
        "client_id" => application.client_id,
        "client_secret" => application.client_secret,
        "scope" => "applications:write"
      }

      token_conn = post(conn, ~p"/#{organization.slug}/oauth/token", params)
      token_response = json_response(token_conn, 200)
      access_token = token_response["access_token"]

      # Regenerate secret via API
      api_conn =
        conn
        |> put_req_header("authorization", "Bearer #{access_token}")
        |> put_req_header("accept", "application/json")

      response =
        post(api_conn, ~p"/#{organization.slug}/api/applications/#{app.id}/regenerate-secret")

      assert json_response(response, 200)

      # Give async task time to complete
      Process.sleep(100)

      events =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "oauth_client_secret_regenerated"
        )

      assert length(events) == 1

      event = hd(events)
      assert event.actor_type == "application"
      assert event.actor_id == application.id
      assert event.actor_name == application.name
      assert event.resource_type == "oauth_application"
      assert event.resource_id == app.id
      assert event.outcome == "success"
    end
  end
end
