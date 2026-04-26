defmodule AuthifyTest.SAMLServiceProvider do
  @moduledoc false

  defstruct [:private_key, :certificate, :entity_id, :acs_url, :sls_url, :org, :sp_record]

  def new(org, attrs \\ %{}) do
    private_key = X509.PrivateKey.new_rsa(2048)

    certificate =
      X509.Certificate.self_signed(
        private_key,
        "/C=US/O=Test SP/CN=Test SAML SP",
        template: :server
      )

    key_pem = X509.PrivateKey.to_pem(private_key)
    cert_pem = X509.Certificate.to_pem(certificate)

    uid = :crypto.strong_rand_bytes(8) |> Base.hex_encode32(case: :lower)
    entity_id = Map.get(attrs, :entity_id, "https://sp-#{uid}.example.com")
    acs_url = Map.get(attrs, :acs_url, "#{entity_id}/saml/acs")
    sls_url = Map.get(attrs, :sls_url, "#{entity_id}/saml/sls")

    {:ok, sp_record} =
      Authify.SAML.create_service_provider(%{
        name: Map.get(attrs, :name, "Test SP #{uid}"),
        entity_id: entity_id,
        acs_url: acs_url,
        sls_url: sls_url,
        certificate: cert_pem,
        metadata: nil,
        attribute_mapping: Jason.encode!(%{}),
        sign_requests: true,
        sign_assertions: true,
        encrypt_assertions: false,
        is_active: true,
        organization_id: org.id
      })

    %__MODULE__{
      private_key: key_pem,
      certificate: cert_pem,
      entity_id: entity_id,
      acs_url: acs_url,
      sls_url: sls_url,
      org: org,
      sp_record: sp_record
    }
  end

  def build_authn_request(%__MODULE__{} = sp) do
    request_id = generate_id()
    now = DateTime.utc_now()
    unsigned_xml = build_authn_request_xml(sp, request_id, now)
    signed_xml = sign_xml(unsigned_xml, sp)
    {:ok, {Base.encode64(signed_xml), request_id}}
  end

  def extract_response(%{resp_body: body}) do
    case Regex.run(~r/name="SAMLResponse" value="([^"]+)"/, body) do
      [_, b64] ->
        case Base.decode64(b64) do
          {:ok, xml} -> {:ok, xml}
          :error -> {:error, :invalid_base64}
        end

      nil ->
        {:error, :saml_response_not_found}
    end
  end

  # ── Private Helpers ──

  defp build_authn_request_xml(sp, request_id, now) do
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <saml2p:AuthnRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                       xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                       ID="#{request_id}"
                       IssueInstant="#{DateTime.to_iso8601(now)}"
                       Version="2.0"
                       AssertionConsumerServiceURL="#{sp.acs_url}"
                       Destination="#{AuthifyWeb.Endpoint.url()}/#{sp.org.slug}/saml/sso">
      <saml2:Issuer>#{sp.entity_id}</saml2:Issuer>
      <saml2p:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"/>
    </saml2p:AuthnRequest>
    """
    |> String.trim()
  end

  defp sign_xml(xml_string, %__MODULE__{} = sp) do
    canonical_xml = Authify.SAML.XMLSignature.canonicalize_xml(xml_string)
    digest = :crypto.hash(:sha256, canonical_xml)
    digest_b64 = Base.encode64(digest)

    signed_info =
      """
      <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>#{digest_b64}</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      """
      |> String.trim()

    canonical_signed_info = Authify.SAML.XMLSignature.canonicalize_xml(signed_info)

    [pem_entry] = :public_key.pem_decode(sp.private_key)
    private_key = :public_key.pem_entry_decode(pem_entry)
    sig_bytes = :public_key.sign(canonical_signed_info, :sha256, private_key)
    sig_b64 = Base.encode64(sig_bytes)

    cert_b64 =
      sp.certificate
      |> String.replace("-----BEGIN CERTIFICATE-----", "")
      |> String.replace("-----END CERTIFICATE-----", "")
      |> String.replace(~r/\s/, "")

    signature_element =
      """
      <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        #{signed_info}
        <ds:SignatureValue>#{sig_b64}</ds:SignatureValue>
        <ds:KeyInfo>
          <ds:X509Data>
            <ds:X509Certificate>#{cert_b64}</ds:X509Certificate>
          </ds:KeyInfo>
        </ds:KeyInfo>
      </ds:Signature>
      """
      |> String.trim()

    # Insert signature after the first Issuer element (SAML convention)
    String.replace(
      xml_string,
      ~r/(<saml2:Issuer[^>]*>.*?<\/saml2:Issuer>)/s,
      "\\1\n  #{signature_element}"
    )
  end

  defp generate_id do
    "_" <> (:crypto.strong_rand_bytes(20) |> Base.hex_encode32(case: :lower))
  end
end
