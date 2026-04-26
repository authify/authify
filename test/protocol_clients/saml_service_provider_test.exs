defmodule AuthifyTest.SAMLServiceProviderTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  alias AuthifyTest.SAMLServiceProvider

  describe "new/2" do
    setup do: %{org: organization_fixture()}

    test "generates an RSA private key (PEM)", %{org: org} do
      sp = SAMLServiceProvider.new(org)
      assert is_binary(sp.private_key)
      assert String.contains?(sp.private_key, "PRIVATE KEY")
      assert [_] = :public_key.pem_decode(sp.private_key)
    end

    test "generates a self-signed X.509 certificate (PEM)", %{org: org} do
      sp = SAMLServiceProvider.new(org)
      assert is_binary(sp.certificate)
      assert String.contains?(sp.certificate, "BEGIN CERTIFICATE")
      [pem_entry] = :public_key.pem_decode(sp.certificate)
      cert = :public_key.pem_entry_decode(pem_entry)
      assert match?({:Certificate, _, _, _}, cert)
    end

    test "registers a service provider record in the database", %{org: org} do
      sp = SAMLServiceProvider.new(org)
      assert sp.sp_record.id
      assert sp.sp_record.organization_id == org.id
      assert sp.sp_record.is_active
    end

    test "each call produces a unique entity_id", %{org: org} do
      sp1 = SAMLServiceProvider.new(org)
      sp2 = SAMLServiceProvider.new(org)
      refute sp1.entity_id == sp2.entity_id
    end

    test "accepts an explicit entity_id override via attrs", %{org: org} do
      sp = SAMLServiceProvider.new(org, %{entity_id: "https://custom-sp.example.com"})
      assert sp.entity_id == "https://custom-sp.example.com"
      assert sp.sp_record.entity_id == "https://custom-sp.example.com"
    end

    test "stores the SP certificate PEM in the DB record", %{org: org} do
      sp = SAMLServiceProvider.new(org)
      assert String.contains?(sp.sp_record.certificate, "BEGIN CERTIFICATE")
    end
  end

  describe "build_authn_request/1" do
    setup do: %{org: organization_fixture()}

    test "returns a Base64-encoded XML string and a request ID", %{org: org} do
      sp = SAMLServiceProvider.new(org)
      assert {:ok, {encoded, request_id}} = SAMLServiceProvider.build_authn_request(sp)
      assert is_binary(encoded)
      assert is_binary(request_id) and String.starts_with?(request_id, "_")
      xml = Base.decode64!(encoded)
      assert String.contains?(xml, "<?xml")
      assert String.contains?(xml, "<saml2p:AuthnRequest")
    end

    test "XML contains required SAML AuthnRequest elements", %{org: org} do
      sp = SAMLServiceProvider.new(org)
      {:ok, {encoded, request_id}} = SAMLServiceProvider.build_authn_request(sp)
      xml = Base.decode64!(encoded)

      assert String.contains?(xml, request_id)
      assert String.contains?(xml, "IssueInstant")
      assert String.contains?(xml, sp.entity_id)
      assert String.contains?(xml, sp.acs_url)
      assert String.contains?(xml, "AuthnRequest")
    end

    test "AuthnRequest contains a ds:Signature element", %{org: org} do
      sp = SAMLServiceProvider.new(org)
      {:ok, {encoded, _}} = SAMLServiceProvider.build_authn_request(sp)
      xml = Base.decode64!(encoded)

      assert String.contains?(xml, "<ds:Signature")
      assert String.contains?(xml, "<ds:SignatureValue>")
      assert String.contains?(xml, "<ds:DigestValue>")
    end

    test "SignatureValue is valid RSA-SHA256 base64 of correct length", %{org: org} do
      sp = SAMLServiceProvider.new(org)
      {:ok, {encoded, _}} = SAMLServiceProvider.build_authn_request(sp)
      xml = Base.decode64!(encoded)

      [_, sig_b64] = Regex.run(~r/<ds:SignatureValue>([\s\S]*?)<\/ds:SignatureValue>/, xml)
      assert {:ok, sig_bytes} = Base.decode64(String.trim(sig_b64))
      # RSA-2048 signatures are 256 bytes
      assert byte_size(sig_bytes) == 256
    end
  end

  describe "extract_response/1" do
    test "decodes SAMLResponse from an auto-submit HTML form" do
      xml = "<saml2p:Response>test content</saml2p:Response>"
      encoded = Base.encode64(xml)

      html_body = """
      <html>
      <body onload="document.forms[0].submit()">
        <form method="post" action="https://sp.example.com/saml/acs">
          <input type="hidden" name="SAMLResponse" value="#{encoded}" />
          <input type="submit" value="Continue" />
        </form>
      </body>
      </html>
      """

      fake_conn = %Plug.Conn{resp_body: html_body}
      assert {:ok, ^xml} = SAMLServiceProvider.extract_response(fake_conn)
    end

    test "returns error when no SAMLResponse field is present" do
      fake_conn = %Plug.Conn{resp_body: "<html><body>no form</body></html>"}
      assert {:error, :saml_response_not_found} = SAMLServiceProvider.extract_response(fake_conn)
    end

    test "returns error when SAMLResponse value is invalid base64" do
      html_body = ~s(<form><input name="SAMLResponse" value="not!!valid!!base64" /></form>)
      fake_conn = %Plug.Conn{resp_body: html_body}
      assert {:error, :invalid_base64} = SAMLServiceProvider.extract_response(fake_conn)
    end
  end

  describe "validate_response/4" do
    setup do
      org = organization_fixture()
      sp = SAMLServiceProvider.new(org)
      now = DateTime.utc_now()
      expires = DateTime.add(now, 300, :second)
      request_id = "_req_#{:crypto.strong_rand_bytes(4) |> Base.hex_encode32(case: :lower)}"

      valid_xml = build_test_response_xml(sp, org, request_id, now, expires)

      %{
        org: org,
        sp: sp,
        request_id: request_id,
        valid_xml: valid_xml,
        now: now,
        expires: expires
      }
    end

    test "parses a valid assertion into the expected map shape", %{
      sp: sp,
      org: org,
      valid_xml: valid_xml,
      request_id: request_id
    } do
      conn = build_conn()

      assert {:ok, assertion} =
               SAMLServiceProvider.validate_response(sp, valid_xml, org,
                 in_response_to: request_id,
                 verify_signature: false,
                 conn: conn
               )

      assert assertion.name_id == "test-subject-id"
      assert assertion.session_index == "test-session-1"
      assert assertion.in_response_to == request_id
      assert is_map(assertion.attributes)
    end

    test "rejects an expired assertion", %{sp: sp, org: org, request_id: request_id, now: now} do
      conn = build_conn()
      past = DateTime.add(now, -600, :second)
      expired_xml = build_test_response_xml(sp, org, request_id, now, past)

      assert {:error, :assertion_expired} =
               SAMLServiceProvider.validate_response(sp, expired_xml, org,
                 in_response_to: request_id,
                 verify_signature: false,
                 conn: conn
               )
    end

    test "rejects a response with wrong audience", %{
      sp: sp,
      org: org,
      request_id: request_id,
      now: now,
      expires: expires
    } do
      conn = build_conn()

      wrong_audience_xml =
        build_test_response_xml(sp, org, request_id, now, expires,
          audience: "https://wrong-sp.example.com"
        )

      assert {:error, :wrong_audience} =
               SAMLServiceProvider.validate_response(sp, wrong_audience_xml, org,
                 in_response_to: request_id,
                 verify_signature: false,
                 conn: conn
               )
    end

    test "rejects a response with wrong Recipient", %{
      sp: sp,
      org: org,
      request_id: request_id,
      now: now,
      expires: expires
    } do
      conn = build_conn()

      wrong_recipient_xml =
        build_test_response_xml(sp, org, request_id, now, expires,
          recipient: "https://attacker.example.com/acs"
        )

      assert {:error, :wrong_recipient} =
               SAMLServiceProvider.validate_response(sp, wrong_recipient_xml, org,
                 in_response_to: request_id,
                 verify_signature: false,
                 conn: conn
               )
    end

    test "rejects a response when InResponseTo does not match", %{
      sp: sp,
      org: org,
      valid_xml: valid_xml
    } do
      conn = build_conn()

      assert {:error, :in_response_to_mismatch} =
               SAMLServiceProvider.validate_response(sp, valid_xml, org,
                 in_response_to: "_completely_different_id",
                 verify_signature: false,
                 conn: conn
               )
    end

    test "extracts attributes from AttributeStatement", %{
      sp: sp,
      org: org,
      request_id: request_id,
      now: now,
      expires: expires
    } do
      conn = build_conn()

      xml_with_attrs =
        build_test_response_xml(sp, org, request_id, now, expires,
          attributes: [{"email", "alice@example.com"}, {"firstName", "Alice"}]
        )

      assert {:ok, assertion} =
               SAMLServiceProvider.validate_response(sp, xml_with_attrs, org,
                 in_response_to: request_id,
                 verify_signature: false,
                 conn: conn
               )

      assert assertion.attributes["email"] == "alice@example.com"
      assert assertion.attributes["firstName"] == "Alice"
    end
  end

  describe "build_logout_request/2" do
    setup do: %{org: organization_fixture()}

    test "returns Base64-encoded XML and a request ID", %{org: org} do
      sp = SAMLServiceProvider.new(org)
      assert {:ok, {encoded, request_id}} = SAMLServiceProvider.build_logout_request(sp, "sess-1")
      assert is_binary(encoded)
      assert String.starts_with?(request_id, "_")
      xml = Base.decode64!(encoded)
      assert String.contains?(xml, "LogoutRequest")
    end

    test "LogoutRequest XML contains the given SessionIndex", %{org: org} do
      sp = SAMLServiceProvider.new(org)
      {:ok, {encoded, _}} = SAMLServiceProvider.build_logout_request(sp, "my-session-index")
      xml = Base.decode64!(encoded)
      assert String.contains?(xml, "my-session-index")
    end

    test "LogoutRequest is signed with ds:Signature", %{org: org} do
      sp = SAMLServiceProvider.new(org)
      {:ok, {encoded, _}} = SAMLServiceProvider.build_logout_request(sp, "sess-1")
      xml = Base.decode64!(encoded)
      assert String.contains?(xml, "<ds:Signature")
    end
  end

  describe "validate_logout_response/2" do
    setup do: %{org: organization_fixture()}

    test "returns {:ok, :logged_out} for a Success status response", %{org: org} do
      sp = SAMLServiceProvider.new(org)

      logout_xml =
        build_logout_response_xml(sp, org, "urn:oasis:names:tc:SAML:2.0:status:Success")

      encoded = Base.encode64(logout_xml)
      html = ~s(<form><input name="SAMLResponse" value="#{encoded}" /></form>)
      fake_conn = %Plug.Conn{resp_body: html}
      assert {:ok, :logged_out} = SAMLServiceProvider.validate_logout_response(sp, fake_conn)
    end

    test "returns {:error, {:unexpected_status, _}} for a non-Success status", %{org: org} do
      sp = SAMLServiceProvider.new(org)

      logout_xml =
        build_logout_response_xml(sp, org, "urn:oasis:names:tc:SAML:2.0:status:Requester")

      encoded = Base.encode64(logout_xml)
      html = ~s(<form><input name="SAMLResponse" value="#{encoded}" /></form>)
      fake_conn = %Plug.Conn{resp_body: html}

      assert {:error, {:unexpected_status, "urn:oasis:names:tc:SAML:2.0:status:Requester"}} =
               SAMLServiceProvider.validate_logout_response(sp, fake_conn)
    end
  end

  # ── Private Test Helpers ──

  defp build_test_response_xml(sp, org, request_id, now, expires, opts \\ []) do
    audience = Keyword.get(opts, :audience, sp.entity_id)
    recipient = Keyword.get(opts, :recipient, sp.acs_url)
    attributes = Keyword.get(opts, :attributes, [])
    issuer = "#{AuthifyWeb.Endpoint.url()}/#{org.slug}/saml/metadata"
    not_before = DateTime.to_iso8601(DateTime.add(now, -5, :second))

    attr_xml =
      if attributes == [] do
        ""
      else
        attr_elements =
          Enum.map_join(attributes, "\n", fn {name, value} ->
            """
            <saml2:Attribute Name="#{name}">
              <saml2:AttributeValue>#{value}</saml2:AttributeValue>
            </saml2:Attribute>
            """
          end)

        "<saml2:AttributeStatement>#{attr_elements}</saml2:AttributeStatement>"
      end

    """
    <?xml version="1.0" encoding="UTF-8"?>
    <saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                   xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                   ID="_resp_test"
                   InResponseTo="#{request_id}"
                   IssueInstant="#{DateTime.to_iso8601(now)}"
                   Destination="#{sp.acs_url}"
                   Version="2.0">
      <saml2:Issuer>#{issuer}</saml2:Issuer>
      <saml2p:Status>
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
      </saml2p:Status>
      <saml2:Assertion ID="_assert_test"
                   IssueInstant="#{DateTime.to_iso8601(now)}"
                   Version="2.0">
        <saml2:Issuer>#{issuer}</saml2:Issuer>
        <saml2:Subject>
          <saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">test-subject-id</saml2:NameID>
          <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml2:SubjectConfirmationData InResponseTo="#{request_id}"
                                           NotOnOrAfter="#{DateTime.to_iso8601(expires)}"
                                           Recipient="#{recipient}"/>
          </saml2:SubjectConfirmation>
        </saml2:Subject>
        <saml2:Conditions NotBefore="#{not_before}"
                       NotOnOrAfter="#{DateTime.to_iso8601(expires)}">
          <saml2:AudienceRestriction>
            <saml2:Audience>#{audience}</saml2:Audience>
          </saml2:AudienceRestriction>
        </saml2:Conditions>
        <saml2:AuthnStatement SessionIndex="test-session-1">
          <saml2:AuthnContext>
            <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
          </saml2:AuthnContext>
        </saml2:AuthnStatement>
        #{attr_xml}
      </saml2:Assertion>
    </saml2p:Response>
    """
    |> String.trim()
  end

  defp build_logout_response_xml(sp, org, status_code) do
    now = DateTime.to_iso8601(DateTime.utc_now())

    """
    <?xml version="1.0" encoding="UTF-8"?>
    <saml2p:LogoutResponse xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                       xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                       ID="_logout_resp_test"
                       InResponseTo="_logout_req_test"
                       IssueInstant="#{now}"
                       Destination="#{sp.sls_url}"
                       Version="2.0">
      <saml2:Issuer>#{AuthifyWeb.Endpoint.url()}/#{org.slug}/saml/metadata</saml2:Issuer>
      <saml2p:Status>
        <saml2p:StatusCode Value="#{status_code}"/>
      </saml2p:Status>
    </saml2p:LogoutResponse>
    """
    |> String.trim()
  end
end
