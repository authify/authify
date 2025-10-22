defmodule Authify.SAML.CertificateTest do
  @moduledoc """
  Tests for SAML.Certificate schema, specifically focusing on private key encryption.
  """
  use Authify.DataCase, async: true

  alias Authify.Accounts
  alias Authify.SAML.Certificate

  describe "private_key encryption" do
    setup do
      # Create a test organization
      {:ok, org} =
        Accounts.create_organization(%{
          name: "Test Org",
          slug: "test-org-#{System.unique_integer([:positive])}"
        })

      {:ok, organization: org}
    end

    test "encrypts private_key on insert", %{organization: org} do
      private_key_pem = """
      -----BEGIN PRIVATE KEY-----
      MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
      MzEfYyjiWA4R4/M2bS1+fWIcPm15A8SE0H0D1WI4OW5GD2+9hBSBo+kgKSkNb8sR
      -----END PRIVATE KEY-----
      """

      certificate_pem = """
      -----BEGIN CERTIFICATE-----
      MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKUzMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
      BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
      -----END CERTIFICATE-----
      """

      attrs = %{
        name: "Test SAML Cert",
        purpose: "signing",
        certificate: certificate_pem,
        private_key: private_key_pem,
        expires_at: DateTime.utc_now() |> DateTime.add(365, :day),
        organization_id: org.id
      }

      changeset = Certificate.changeset(%Certificate{}, attrs)
      assert changeset.valid?

      {:ok, cert} = Repo.insert(changeset)

      # Verify the private_key was inserted
      assert cert.private_key == private_key_pem

      # Now fetch from database to verify encryption/decryption works
      loaded_cert = Repo.get!(Certificate, cert.id)
      assert loaded_cert.private_key == private_key_pem

      # Verify it's actually encrypted in the database by querying raw SQL
      result =
        Repo.query!(
          "SELECT private_key FROM saml_certificates WHERE id = ?",
          [cert.id]
        )

      [[encrypted_value]] = result.rows

      # The encrypted value should NOT match the plaintext
      refute encrypted_value == private_key_pem

      # The encrypted value should be a base64-encoded string (encrypted format)
      assert is_binary(encrypted_value)
      assert String.length(encrypted_value) > 0

      # It should be valid base64
      assert match?({:ok, _}, Base.decode64(encrypted_value))
    end

    test "decrypts private_key on load", %{organization: org} do
      private_key_pem = """
      -----BEGIN RSA PRIVATE KEY-----
      MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tfn1iHD5teQPEhNB9
      A9ViODluRg9vvYQUgaPpICkpDW/LEQo=
      -----END RSA PRIVATE KEY-----
      """

      certificate_pem = """
      -----BEGIN CERTIFICATE-----
      MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKUzMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
      -----END CERTIFICATE-----
      """

      {:ok, cert} =
        %Certificate{}
        |> Certificate.changeset(%{
          name: "Decryption Test",
          purpose: "encryption",
          certificate: certificate_pem,
          private_key: private_key_pem,
          expires_at: DateTime.utc_now() |> DateTime.add(365, :day),
          organization_id: org.id
        })
        |> Repo.insert()

      # Load from database
      loaded = Repo.get!(Certificate, cert.id)

      # Should decrypt to original value
      assert loaded.private_key == private_key_pem
    end

    test "handles nil private_key", %{organization: org} do
      # This should fail validation since private_key is required
      changeset =
        Certificate.changeset(%Certificate{}, %{
          name: "No Key",
          purpose: "signing",
          certificate: "-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----",
          private_key: nil,
          expires_at: DateTime.utc_now() |> DateTime.add(365, :day),
          organization_id: org.id
        })

      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).private_key
    end

    test "excludes private_key from JSON encoding", %{organization: org} do
      {:ok, cert} =
        %Certificate{}
        |> Certificate.changeset(%{
          name: "JSON Test",
          purpose: "signing",
          certificate: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
          private_key: "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
          expires_at: DateTime.utc_now() |> DateTime.add(365, :day),
          organization_id: org.id
        })
        |> Repo.insert()

      json = Jason.encode!(cert)
      decoded = Jason.decode!(json)

      # Should not contain private_key
      refute Map.has_key?(decoded, "private_key")

      # Should contain other fields
      assert decoded["name"] == "JSON Test"
      assert decoded["purpose"] == "signing"
    end
  end
end
