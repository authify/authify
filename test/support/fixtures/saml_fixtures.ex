defmodule Authify.SAMLFixtures do
  @moduledoc """
  This module defines test helpers for creating
  SAML entities via the `Authify.SAML` context.
  """

  @doc """
  Generate a SAML service provider.
  """
  def service_provider_fixture(attrs \\ %{}) do
    # Convert to map if it's a keyword list
    attrs = if is_list(attrs), do: Enum.into(attrs, %{}), else: attrs

    organization =
      case Map.get(attrs, :organization) do
        nil -> Authify.AccountsFixtures.organization_fixture()
        org -> org
      end

    attrs =
      attrs
      |> Map.drop([:organization])
      |> Enum.into(%{
        name: "Test Service Provider",
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
        is_active: true,
        organization_id: organization.id
      })

    {:ok, service_provider} = Authify.SAML.create_service_provider(attrs)

    # Load the organization relationship
    service_provider
    |> Authify.Repo.preload(:organization)
  end

  @doc """
  Generate a SAML session.
  """
  def saml_session_fixture(attrs \\ %{}) do
    service_provider = attrs[:service_provider] || service_provider_fixture()

    user =
      attrs[:user] ||
        Authify.AccountsFixtures.user_for_organization_fixture(service_provider.organization)

    session_id = Authify.SAML.Session.generate_session_id()
    subject_id = Authify.SAML.Session.generate_subject_id(user, service_provider)

    attrs =
      attrs
      |> Map.drop([:service_provider, :user])
      |> Enum.into(%{
        session_id: session_id,
        subject_id: subject_id,
        request_id:
          "test_request_#{:crypto.strong_rand_bytes(8) |> Base.hex_encode32(case: :lower)}",
        relay_state: "test_relay_state",
        issued_at: DateTime.utc_now() |> DateTime.truncate(:second),
        expires_at:
          DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.truncate(:second),
        user_id: user.id,
        service_provider_id: service_provider.id
      })

    {:ok, saml_session} = Authify.SAML.create_session(attrs)

    # Load relationships
    saml_session
    |> Authify.Repo.preload([:user, :service_provider])
  end

  @doc """
  Generate a SAML certificate.
  """
  def certificate_fixture(attrs \\ %{}) do
    # Convert to map if it's a keyword list
    attrs = if is_list(attrs), do: Enum.into(attrs, %{}), else: attrs

    organization =
      case Map.get(attrs, :organization) do
        nil -> Authify.AccountsFixtures.organization_fixture()
        org -> org
      end

    # Generate a real test certificate
    {cert_pem, key_pem} = generate_test_certificate()

    attrs =
      attrs
      |> Map.drop([:organization])
      |> Enum.into(%{
        name: "Test Certificate",
        certificate: cert_pem,
        private_key: key_pem,
        purpose: "signing",
        expires_at:
          DateTime.utc_now()
          |> DateTime.add(365 * 24 * 3600, :second)
          |> DateTime.truncate(:second),
        is_active: true,
        organization_id: organization.id
      })

    {:ok, certificate} = Authify.SAML.create_certificate(attrs)

    # Load the organization relationship
    certificate
    |> Authify.Repo.preload(:organization)
  end

  # Generate a real RSA certificate for testing
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

  @doc """
  Generate a sample SAML authentication request XML.
  """
  def sample_saml_request(issuer \\ "https://sp.example.com") do
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <saml2p:AuthnRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                         xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                         ID="test_request_id_#{:crypto.strong_rand_bytes(8) |> Base.hex_encode32(case: :lower)}"
                         IssueInstant="#{DateTime.utc_now() |> DateTime.to_iso8601()}"
                         Version="2.0"
                         AssertionConsumerServiceURL="https://sp.example.com/saml/acs"
                         Destination="https://idp.example.com/saml/sso">
      <saml2:Issuer>#{issuer}</saml2:Issuer>
      <saml2p:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"/>
    </saml2p:AuthnRequest>
    """
  end

  @doc """
  Generate a sample SAML logout request XML.
  """
  def sample_saml_logout_request(issuer \\ "https://sp.example.com") do
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <saml2p:LogoutRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                          xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                          ID="test_logout_request_id_#{:crypto.strong_rand_bytes(8) |> Base.hex_encode32(case: :lower)}"
                          IssueInstant="#{DateTime.utc_now() |> DateTime.to_iso8601()}"
                          Version="2.0"
                          Destination="https://idp.example.com/saml/slo">
      <saml2:Issuer>#{issuer}</saml2:Issuer>
      <saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">test_subject_id</saml2:NameID>
      <saml2p:SessionIndex>test_session_index</saml2p:SessionIndex>
    </saml2p:LogoutRequest>
    """
  end

  @doc """
  Generate Base64-encoded SAML request (as sent via HTTP-Redirect binding).
  """
  def encoded_saml_request(issuer \\ "https://sp.example.com") do
    sample_saml_request(issuer) |> Base.encode64()
  end

  @doc """
  Generate Base64-encoded SAML logout request.
  """
  def encoded_saml_logout_request(issuer \\ "https://sp.example.com") do
    sample_saml_logout_request(issuer) |> Base.encode64()
  end
end
