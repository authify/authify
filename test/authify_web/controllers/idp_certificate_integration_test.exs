defmodule AuthifyWeb.IdPCertificateIntegrationTest do
  @moduledoc """
  Integration tests for IdP Certificates.

  These tests verify:
  - Certificates can be created and managed per organization
  - Certificates are scoped to organizations
  - Active certificates can be retrieved
  """
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures

  describe "IdP Certificate management" do
    test "organization can generate and list certificates" do
      org = organization_fixture()

      # Generate a certificate
      {:ok, cert} =
        Authify.Accounts.generate_certificate(org, %{
          "name" => "Primary Certificate",
          "is_active" => true
        })

      assert cert.name == "Primary Certificate"
      assert cert.organization_id == org.id
      assert cert.is_active == true
      assert cert.certificate
      assert cert.private_key

      # List certificates for the organization
      certs = Authify.Accounts.list_certificates(org)
      assert length(certs) == 1
      assert hd(certs).id == cert.id
    end

    test "can retrieve active SAML signing certificate" do
      org = organization_fixture()

      # Generate a SAML signing certificate
      {:ok, cert} =
        Authify.Accounts.generate_saml_signing_certificate(org, %{
          "name" => "SAML Signing Cert"
        })

      assert cert.usage == "saml_signing"
      # Note: is_active may be false by default, activate if needed
      cert =
        if cert.is_active,
          do: cert,
          else: elem(Authify.Accounts.update_certificate(cert, %{"is_active" => true}), 1)

      # Retrieve active certificate
      active_cert = Authify.Accounts.get_active_saml_signing_certificate(org)
      assert active_cert.id == cert.id
      assert active_cert.usage == "saml_signing"
    end

    test "certificates are scoped to organizations" do
      org_a = organization_fixture(%{slug: "org-a"})
      org_b = organization_fixture(%{slug: "org-b"})

      {:ok, cert_a} =
        Authify.Accounts.generate_certificate(org_a, %{
          "name" => "Certificate A",
          "is_active" => true
        })

      {:ok, _cert_b} =
        Authify.Accounts.generate_certificate(org_b, %{
          "name" => "Certificate B",
          "is_active" => true
        })

      # Org A can only see its own cert
      certs_a = Authify.Accounts.list_certificates(org_a)
      assert length(certs_a) == 1
      assert hd(certs_a).id == cert_a.id

      # Org B can only see its own cert
      certs_b = Authify.Accounts.list_certificates(org_b)
      assert length(certs_b) == 1
      refute hd(certs_b).id == cert_a.id
    end

    test "can deactivate and activate certificates" do
      org = organization_fixture()

      {:ok, cert} =
        Authify.Accounts.generate_certificate(org, %{
          "name" => "Test Certificate",
          "is_active" => true
        })

      assert cert.is_active == true

      # Deactivate
      {:ok, updated_cert} =
        Authify.Accounts.update_certificate(cert, %{"is_active" => false})

      assert updated_cert.is_active == false

      # Reactivate
      {:ok, reactivated_cert} =
        Authify.Accounts.update_certificate(updated_cert, %{"is_active" => true})

      assert reactivated_cert.is_active == true
    end

    test "can delete certificates" do
      org = organization_fixture()

      {:ok, cert} =
        Authify.Accounts.generate_certificate(org, %{
          "name" => "Temporary Certificate",
          "is_active" => true
        })

      # Certificate exists
      certs_before = Authify.Accounts.list_certificates(org)
      assert length(certs_before) == 1

      # Delete it
      {:ok, _deleted} = Authify.Accounts.delete_certificate(cert)

      # Certificate is gone
      certs_after = Authify.Accounts.list_certificates(org)
      assert Enum.empty?(certs_after)
    end
  end
end
