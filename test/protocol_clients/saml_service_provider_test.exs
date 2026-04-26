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
end
