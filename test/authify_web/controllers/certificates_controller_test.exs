defmodule AuthifyWeb.CertificatesControllerTest do
  @moduledoc false
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures

  alias Authify.Accounts
  alias Authify.AuditLog

  setup %{conn: conn} do
    organization = organization_fixture()
    admin = user_fixture(organization: organization, role: "admin")

    conn =
      conn
      |> log_in_user(admin)

    %{conn: conn, organization: organization}
  end

  describe "POST /:org_slug/certificates" do
    test "manual upload logs audit event", %{conn: conn, organization: organization} do
      {certificate_pem, private_key_pem} = sample_pems(organization)

      params = %{
        "certificate" => %{
          "name" => "Manual Upload Cert",
          "usage" => "saml_signing",
          "certificate" => certificate_pem,
          "private_key" => private_key_pem,
          "is_active" => "false"
        }
      }

      conn = post(conn, "/#{organization.slug}/certificates", params)

      assert redirected_to(conn) =~ "/#{organization.slug}/certificates/"

      created_certificate =
        Accounts.list_certificates(organization)
        |> Enum.find(&(&1.name == "Manual Upload Cert"))

      assert created_certificate

      events =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "certificate_created"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "success"
      assert event.metadata["source"] == "web"
      assert event.metadata["generated"] == false
      assert event.metadata["certificate_id"] == created_certificate.id
    end

    test "invalid upload logs failure", %{conn: conn, organization: organization} do
      conn =
        post(conn, "/#{organization.slug}/certificates", %{
          "certificate" => %{
            "name" => "",
            "usage" => "saml_signing"
          }
        })

      assert html_response(conn, 200)

      events =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "certificate_created"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "failure"
      assert event.metadata["source"] == "web"
      assert Enum.any?(event.metadata["errors"], &String.contains?(&1, "name"))
    end
  end

  describe "PATCH /:org_slug/certificates/:id/activate" do
    test "activation is logged", %{conn: conn, organization: organization} do
      {certificate_pem, private_key_pem} = sample_pems(organization)

      {:ok, certificate} =
        Accounts.create_certificate(organization, %{
          "name" => "Inactive Cert",
          "usage" => "saml_signing",
          "certificate" => certificate_pem,
          "private_key" => private_key_pem,
          "is_active" => false
        })

      conn = patch(conn, "/#{organization.slug}/certificates/#{certificate.id}/activate")

      assert redirected_to(conn) == "/#{organization.slug}/certificates/#{certificate.id}"

      events =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "certificate_activated"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "success"
      assert event.metadata["source"] == "web"
      assert event.metadata["certificate_id"] == certificate.id
      assert event.metadata["previous_state"]["is_active"] == false
    end
  end

  describe "PATCH /:org_slug/certificates/:id/deactivate" do
    test "deactivation is logged", %{conn: conn, organization: organization} do
      {certificate_pem, private_key_pem} = sample_pems(organization)

      {:ok, certificate} =
        Accounts.create_certificate(organization, %{
          "name" => "Active Cert",
          "usage" => "saml_signing",
          "certificate" => certificate_pem,
          "private_key" => private_key_pem,
          "is_active" => true
        })

      conn = patch(conn, "/#{organization.slug}/certificates/#{certificate.id}/deactivate")

      assert redirected_to(conn) == "/#{organization.slug}/certificates/#{certificate.id}"

      events =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "certificate_deactivated"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "success"
      assert event.metadata["source"] == "web"
      assert event.metadata["certificate_id"] == certificate.id
      assert event.metadata["previous_state"]["is_active"] == true
    end
  end

  describe "DELETE /:org_slug/certificates/:id" do
    test "deletion is logged", %{conn: conn, organization: organization} do
      {certificate_pem, private_key_pem} = sample_pems(organization)

      {:ok, certificate} =
        Accounts.create_certificate(organization, %{
          "name" => "Disposable Cert",
          "usage" => "saml_signing",
          "certificate" => certificate_pem,
          "private_key" => private_key_pem,
          "is_active" => false
        })

      conn = delete(conn, "/#{organization.slug}/certificates/#{certificate.id}")

      assert redirected_to(conn) == "/#{organization.slug}/certificates"

      events =
        AuditLog.list_events(
          organization_id: organization.id,
          event_type: "certificate_deleted"
        )

      assert length(events) == 1
      event = hd(events)
      assert event.outcome == "success"
      assert event.metadata["source"] == "web"
      assert event.metadata["certificate_id"] == certificate.id
    end
  end

  defp sample_pems(organization) do
    {:ok, certificate} =
      Accounts.generate_certificate(organization, %{
        "name" => "Sample PEM",
        "usage" => "saml_signing",
        "is_active" => false
      })

    pem_tuple = {certificate.certificate, certificate.private_key}

    Accounts.delete_certificate(certificate)

    pem_tuple
  end
end
