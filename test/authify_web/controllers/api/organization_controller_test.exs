defmodule AuthifyWeb.API.OrganizationControllerTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  alias Authify.AuditLog

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
      |> assign(:current_scopes, ["organizations:read", "organizations:write"])

    %{conn: conn, admin_user: admin_user, organization: organization}
  end

  describe "GET /api/organization" do
    test "returns organization details with HATEOAS links", %{
      conn: conn,
      organization: organization
    } do
      conn = get(conn, "/#{organization.slug}/api/organization")

      assert %{
               "data" => %{
                 "id" => id,
                 "type" => "organization",
                 "attributes" => attributes,
                 "links" => %{"self" => _self_link}
               },
               "links" => %{"self" => _links_self}
             } = json_response(conn, 200)

      assert id == to_string(organization.id)
      assert attributes["name"] == organization.name
      assert attributes["slug"] == organization.slug
      # excluded from response
      refute Map.has_key?(attributes, "settings")
    end

    test "includes correct API version header", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/api/organization")

      assert ["v1"] = get_resp_header(conn, "x-api-version")
    end

    test "requires appropriate Management API scopes", %{conn: conn, organization: organization} do
      # Set up connection without management scopes
      conn =
        conn
        |> assign(:current_scopes, ["profile:read"])

      conn = get(conn, "/#{organization.slug}/api/organization")

      assert %{
               "error" => %{
                 "type" => "insufficient_scope",
                 "message" => "Insufficient scope to access this resource"
               }
             } = json_response(conn, 403)
    end
  end

  describe "PUT /api/organization/configuration" do
    test "logs settings_updated event on success", %{conn: conn, organization: organization} do
      conn =
        put(conn, "/#{organization.slug}/api/organization/configuration", %{
          "settings" => %{
            "allow_invitations" => "false"
          }
        })

      assert %{"data" => %{"type" => "configuration"}} = json_response(conn, 200)

      events =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "settings_updated"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.actor_type == "user"
      assert event.outcome == "success"

      assert Enum.any?(event.metadata["changes"], fn change ->
               change["field"] == "allow_invitations" and change["new"] == false
             end)

      assert event.metadata["schema"] == "organization"
      assert event.metadata["source"] == "api"
    end

    test "logs settings_updated failure when validation errors", %{
      conn: conn,
      organization: organization
    } do
      conn =
        put(conn, "/#{organization.slug}/api/organization/configuration", %{
          "settings" => %{
            "auth_rate_limit" => "999999"
          }
        })

      assert %{"error" => %{"type" => "validation_error"}} = json_response(conn, 422)

      events =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "settings_updated"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "failure"
      assert Enum.any?(event.metadata["errors"], &String.contains?(&1, "quota"))
      assert event.metadata["schema"] == "organization"
      assert event.metadata["source"] == "api"
    end
  end

  # Note: PUT /api/organization and /api/organization/settings endpoints have been
  # removed in favor of /api/organization/configuration which handles both
  # organization profile (description, website, etc.) and feature toggles
  #
  # See configuration_controller_test.exs for configuration endpoint tests

  describe "content negotiation" do
    test "accepts standard application/json header", %{conn: conn, organization: organization} do
      conn =
        conn
        |> put_req_header("accept", "application/json")
        |> get("/#{organization.slug}/api/organization")

      assert ["v1"] = get_resp_header(conn, "x-api-version")
      assert json_response(conn, 200)
    end

    test "handles unsupported media type gracefully", %{conn: conn, organization: organization} do
      # Test that unsupported media types are properly rejected
      conn =
        conn
        |> put_req_header("accept", "application/xml")

      assert_raise Phoenix.NotAcceptableError, fn ->
        get(conn, "/#{organization.slug}/api/organization")
      end
    end
  end
end
