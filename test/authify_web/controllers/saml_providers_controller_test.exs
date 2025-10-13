defmodule AuthifyWeb.SAMLProvidersControllerTest do
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures
  import Authify.SAMLFixtures

  setup %{conn: conn} do
    organization = organization_fixture()
    admin_user = user_fixture(organization: organization, role: "admin")

    conn =
      conn
      |> log_in_user(admin_user)
      |> assign(:current_user, admin_user)
      |> assign(:current_organization, organization)

    %{conn: conn, admin_user: admin_user, organization: organization}
  end

  describe "audit logging" do
    test "logs service provider creation", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      create_attrs = %{
        name: "Audit Test SP",
        description: "Testing audit logs",
        entity_id: "https://sp.example.com",
        acs_url: "https://sp.example.com/saml/acs"
      }

      post(conn, ~p"/#{organization.slug}/saml_providers", service_provider: create_attrs)

      # Give async task time to complete
      Process.sleep(100)

      events =
        Authify.AuditLog.list_events(
          organization_id: organization.id,
          event_type: "saml_sp_created"
        )

      assert length(events) == 1

      event = hd(events)
      assert event.actor_type == "user"
      assert event.actor_id == admin_user.id
      assert event.resource_type == "saml_service_provider"
      assert event.outcome == "success"
      assert event.metadata["service_provider_name"] == "Audit Test SP"
      assert event.metadata["entity_id"] == "https://sp.example.com"
    end

    test "logs service provider updates", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      service_provider = service_provider_fixture(organization: organization)
      update_attrs = %{name: "Updated for Audit"}

      put(conn, ~p"/#{organization.slug}/saml_providers/#{service_provider}",
        service_provider: update_attrs
      )

      # Give async task time to complete
      Process.sleep(100)

      events =
        Authify.AuditLog.list_events(
          organization_id: organization.id,
          event_type: "saml_sp_updated"
        )

      assert length(events) == 1

      event = hd(events)
      assert event.actor_type == "user"
      assert event.actor_id == admin_user.id
      assert event.resource_type == "saml_service_provider"
      assert event.resource_id == service_provider.id
      assert event.outcome == "success"
    end

    test "logs service provider deletion", %{
      conn: conn,
      organization: organization,
      admin_user: admin_user
    } do
      service_provider = service_provider_fixture(organization: organization)

      delete(conn, ~p"/#{organization.slug}/saml_providers/#{service_provider}")

      # Give async task time to complete
      Process.sleep(100)

      events =
        Authify.AuditLog.list_events(
          organization_id: organization.id,
          event_type: "saml_sp_deleted"
        )

      assert length(events) == 1

      event = hd(events)
      assert event.actor_type == "user"
      assert event.actor_id == admin_user.id
      assert event.resource_type == "saml_service_provider"
      assert event.resource_id == service_provider.id
      assert event.outcome == "success"
      assert event.metadata["entity_id"] == service_provider.entity_id
    end
  end
end
