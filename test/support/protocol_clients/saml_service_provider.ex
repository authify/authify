defmodule AuthifyTest.SAMLServiceProvider do
  @moduledoc false
  @endpoint AuthifyWeb.Endpoint
  import Phoenix.ConnTest
  import SweetXml

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

  def build_logout_request(%__MODULE__{} = sp, session_index) do
    request_id = generate_id()
    now = DateTime.utc_now()

    unsigned_xml =
      """
      <?xml version="1.0" encoding="UTF-8"?>
      <saml2p:LogoutRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                            xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                            ID="#{request_id}"
                            IssueInstant="#{DateTime.to_iso8601(now)}"
                            Version="2.0"
                            Destination="#{AuthifyWeb.Endpoint.url()}/#{sp.org.slug}/saml/slo">
        <saml2:Issuer>#{sp.entity_id}</saml2:Issuer>
        <saml2p:SessionIndex>#{session_index}</saml2p:SessionIndex>
      </saml2p:LogoutRequest>
      """
      |> String.trim()

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
      |> String.replace("-----BEGIN CERTIFICATE----", "")
      |> String.replace("-----END CERTIFICATE----", "")
      |> String.replace(~r/\s/, "")

    signature_element =
      """
      <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        #{signed_info}
        <ds:SignatureValue>#{sig_b64}</ds:SignatureValue>
        <ds:KeyInfo>
          <ds:X509Data>
            <ds:X509Certificate>#{cert_b64}</ds:X509Certificate>
          </ds:X509Data>
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

  # ── Assertion Validation ──

  def validate_response(%__MODULE__{} = sp, response_xml, org, opts \\ []) do
    in_response_to = Keyword.get(opts, :in_response_to)
    verify_sig = Keyword.get(opts, :verify_signature, true)
    clock_skew = Keyword.get(opts, :clock_skew, 60)

    with :ok <- maybe_verify_signature(response_xml, org, verify_sig),
         {:ok, assertion} <- parse_assertion(response_xml),
         :ok <- validate_not_before(assertion.not_before, clock_skew),
         :ok <- validate_not_on_or_after(assertion.not_on_or_after, clock_skew),
         :ok <- validate_audience(assertion.audience, sp.entity_id),
         :ok <- validate_recipient(assertion.recipient, sp.acs_url),
         :ok <- validate_in_response_to(assertion.in_response_to, in_response_to) do
      {:ok, assertion}
    end
  end

  # ── Private Helpers ──

  def validate_logout_response(%__MODULE__{} = _sp, conn) do
    with {:ok, response_xml} <- extract_response(conn) do
      status =
        response_xml
        |> xpath(~x"//saml2p:StatusCode/@Value"s)

      case status do
        "urn:oasis:names:tc:SAML:2.0:status:Success" -> {:ok, :logged_out}
        other -> {:error, {:unexpected_status, other}}
      end
    end
  end

  defp maybe_verify_signature(_xml, _org, false), do: :ok

  defp maybe_verify_signature(xml, org, true) do
    if String.contains?(xml, "<ds:Signature") do
      with {:ok, cert_pem} <- fetch_idp_cert(org) do
        fake_cert = %Authify.Accounts.Certificate{
          certificate: cert_pem,
          private_key: ""
        }

        case Authify.SAML.XMLSignature.verify_signature(xml, fake_cert) do
          {:ok, true} -> :ok
          {:ok, false} -> {:error, :signature_invalid}
          {:error, reason} -> {:error, {:signature_error, reason}}
        end
      end
    else
      :ok
    end
  end

  defp fetch_idp_cert(org) do
    conn = build_conn()
    resp = get(conn, "/#{org.slug}/saml/metadata")

    body = resp.resp_body

    case Regex.run(
           ~r/<[^:]*:X509Certificate[^>]*>([\s\S]*?)<\/[^:]*:X509Certificate>/,
           body
         ) do
      [_, cert_b64] ->
        trimmed = String.trim(cert_b64)

        if trimmed == "" or String.starts_with?(trimmed, "NO_SAML") do
          {:error, :no_idp_signing_cert}
        else
          {:ok, "-----BEGIN CERTIFICATE----\n#{trimmed}\n-----END CERTIFICATE----"}
        end

      nil ->
        {:error, :no_idp_signing_cert}
    end
  end

  defp parse_assertion(response_xml) do
    result =
      xmap(response_xml,
        in_response_to: ~x"//saml2p:Response/@InResponseTo"s,
        name_id: ~x"//saml2:NameID/text()"s,
        not_before: ~x"//saml2:Conditions/@NotBefore"s,
        not_on_or_after: ~x"//saml2:Conditions/@NotOnOrAfter"s,
        audience: ~x"//saml2:Audience/text()"s,
        recipient: ~x"//saml2:SubjectConfirmationData/@Recipient"s,
        subject_not_on_or_after: ~x"//saml2:SubjectConfirmationData/@NotOnOrAfter"s,
        session_index: ~x"//saml2:AuthnStatement/@SessionIndex"s
      )

    attributes = extract_attribute_map(response_xml)
    {:ok, Map.put(result, :attributes, attributes)}
  rescue
    _ -> {:error, :assertion_parse_failed}
  end

  defp extract_attribute_map(response_xml) do
    response_xml
    |> xpath(~x"//saml2:Attribute"l,
      name: ~x"./@Name"s,
      value: ~x"./saml2:AttributeValue/text()"s
    )
    |> Enum.into(%{}, fn %{name: name, value: value} -> {name, value} end)
  rescue
    _ -> %{}
  end

  defp validate_not_before(not_before_str, clock_skew) do
    case DateTime.from_iso8601(not_before_str) do
      {:ok, not_before, _} ->
        adjusted_now = DateTime.add(DateTime.utc_now(), clock_skew, :second)

        if DateTime.compare(not_before, adjusted_now) in [:lt, :eq],
          do: :ok,
          else: {:error, :assertion_not_yet_valid}

      _ ->
        {:error, :invalid_not_before}
    end
  end

  defp validate_not_on_or_after(not_on_or_after_str, clock_skew) do
    case DateTime.from_iso8601(not_on_or_after_str) do
      {:ok, not_on_or_after, _} ->
        adjusted_now = DateTime.add(DateTime.utc_now(), -clock_skew, :second)

        if DateTime.compare(adjusted_now, not_on_or_after) in [:lt, :eq],
          do: :ok,
          else: {:error, :assertion_expired}

      _ ->
        {:error, :invalid_not_on_or_after}
    end
  end

  defp validate_audience(audience, expected_entity_id) do
    if audience == expected_entity_id, do: :ok, else: {:error, :wrong_audience}
  end

  defp validate_recipient(recipient, expected_acs_url) do
    if recipient == expected_acs_url, do: :ok, else: {:error, :wrong_recipient}
  end

  defp validate_in_response_to(_actual, nil), do: :ok

  defp validate_in_response_to(actual, expected) do
    if actual == expected, do: :ok, else: {:error, :in_response_to_mismatch}
  end
end
