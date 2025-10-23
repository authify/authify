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

      # Generate a real certificate for testing
      {cert_pem, key_pem} = generate_test_certificate()

      {:ok, organization: org, certificate_pem: cert_pem, private_key_pem: key_pem}
    end

    test "encrypts private_key on insert", %{
      organization: org,
      certificate_pem: certificate_pem,
      private_key_pem: private_key_pem
    } do
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

    test "decrypts private_key on load", %{
      organization: org,
      certificate_pem: certificate_pem,
      private_key_pem: private_key_pem
    } do
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

    test "excludes private_key from JSON encoding", %{
      organization: org,
      certificate_pem: certificate_pem,
      private_key_pem: private_key_pem
    } do
      {:ok, cert} =
        %Certificate{}
        |> Certificate.changeset(%{
          name: "JSON Test",
          purpose: "signing",
          certificate: certificate_pem,
          private_key: private_key_pem,
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

  # Generate a real RSA certificate for testing
  # This avoids hardcoding private keys in the test file
  defp generate_test_certificate do
    # Generate RSA key pair
    private_key = :public_key.generate_key({:rsa, 2048, 65_537})

    # Create certificate using X509 library helpers
    subject =
      {:rdnSequence,
       [
         [{:AttributeTypeAndValue, {2, 5, 4, 3}, {:utf8String, ~c"Test Certificate"}}]
       ]}

    validity = {
      :Validity,
      {:utcTime, :erlang.universaltime() |> format_time()},
      {:utcTime, :erlang.universaltime() |> add_years(1) |> format_time()}
    }

    public_key_info = {
      :OTPSubjectPublicKeyInfo,
      {:PublicKeyAlgorithm, {1, 2, 840, 113_549, 1, 1, 1}, :NULL},
      {:RSAPublicKey, elem(private_key, 2), elem(private_key, 3)}
    }

    tbs_certificate = {
      :OTPTBSCertificate,
      :v3,
      1,
      {:SignatureAlgorithm, {1, 2, 840, 113_549, 1, 1, 11}, :NULL},
      subject,
      validity,
      subject,
      public_key_info,
      :asn1_NOVALUE,
      :asn1_NOVALUE,
      :asn1_NOVALUE
    }

    # Encode TBS for signing
    tbs_der = :public_key.pkix_encode(:OTPTBSCertificate, tbs_certificate, :otp)

    # Sign the DER-encoded TBS certificate
    signature = :public_key.sign(tbs_der, :sha256, private_key)

    certificate = {
      :OTPCertificate,
      tbs_certificate,
      {:SignatureAlgorithm, {1, 2, 840, 113_549, 1, 1, 11}, :NULL},
      signature
    }

    # Encode to PEM
    cert_der = :public_key.pkix_encode(:OTPCertificate, certificate, :otp)
    cert_pem = :public_key.pem_encode([{:Certificate, cert_der, :not_encrypted}])

    key_der = :public_key.der_encode(:RSAPrivateKey, private_key)
    key_pem = :public_key.pem_encode([{:RSAPrivateKey, key_der, :not_encrypted}])

    {cert_pem, key_pem}
  end

  defp format_time({{year, month, day}, {hour, minute, second}}) do
    year_str = year |> Integer.to_string() |> String.slice(-2, 2)

    :lists.flatten(
      :io_lib.format(~c"~2..0s~2..0B~2..0B~2..0B~2..0B~2..0BZ", [
        year_str,
        month,
        day,
        hour,
        minute,
        second
      ])
    )
  end

  defp add_years({{year, month, day}, time}, years) do
    {{year + years, month, day}, time}
  end
end
