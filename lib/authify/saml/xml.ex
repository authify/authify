defmodule Authify.SAML.XML do
  @moduledoc """
  SAML XML parsing and generation utilities using proper XML libraries.
  """

  import SweetXml
  alias Authify.SAML.{ServiceProvider, Session}
  alias Authify.Accounts.User

  @doc """
  Parse a SAML AuthnRequest from XML or Base64-encoded XML.
  """
  def parse_authn_request(saml_request_data) when is_binary(saml_request_data) do
    case decode_saml_data(saml_request_data) do
      {:ok, xml} ->
        try do
          parsed_request =
            xml
            |> xmap(
              request_id: ~x"//saml2p:AuthnRequest/@ID"s,
              issuer: ~x"//saml2:Issuer/text()"s,
              acs_url: ~x"//saml2p:AuthnRequest/@AssertionConsumerServiceURL"s,
              destination: ~x"//saml2p:AuthnRequest/@Destination"s,
              force_authn: ~x"//saml2p:AuthnRequest/@ForceAuthn"s,
              issue_instant: ~x"//saml2p:AuthnRequest/@IssueInstant"s,
              protocol_binding: ~x"//saml2p:AuthnRequest/@ProtocolBinding"s,
              version: ~x"//saml2p:AuthnRequest/@Version"s
            )

          # Validate required fields
          cond do
            is_nil(parsed_request.request_id) or parsed_request.request_id == "" ->
              {:error, "Missing or empty Request ID"}

            is_nil(parsed_request.issuer) or parsed_request.issuer == "" ->
              {:error, "Missing or empty Issuer"}

            is_nil(parsed_request.acs_url) or parsed_request.acs_url == "" ->
              {:error, "Missing or empty AssertionConsumerServiceURL"}

            true ->
              {:ok,
               %{
                 request_id: parsed_request.request_id,
                 issuer: parsed_request.issuer,
                 acs_url: parsed_request.acs_url,
                 destination: parsed_request.destination,
                 force_authn: parsed_request.force_authn == "true",
                 issue_instant: parsed_request.issue_instant,
                 protocol_binding: parsed_request.protocol_binding,
                 version: parsed_request.version,
                 # RelayState comes from query params, not XML
                 relay_state: nil
               }}
          end
        rescue
          error ->
            {:error, "Failed to parse SAML AuthnRequest: #{inspect(error)}"}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  def parse_authn_request(nil), do: {:error, "SAML request cannot be empty"}
  def parse_authn_request(""), do: {:error, "SAML request cannot be empty"}

  @doc """
  Parse a SAML LogoutRequest from XML or Base64-encoded XML.
  """
  def parse_logout_request(saml_request_data) when is_binary(saml_request_data) do
    case decode_saml_data(saml_request_data) do
      {:ok, xml} ->
        try do
          parsed_request =
            xml
            |> xmap(
              request_id: ~x"//saml2p:LogoutRequest/@ID"s,
              issuer: ~x"//saml2:Issuer/text()"s,
              destination: ~x"//saml2p:LogoutRequest/@Destination"s,
              name_id: ~x"//saml2:NameID/text()"s,
              name_id_format: ~x"//saml2:NameID/@Format"s,
              session_index: ~x"//saml2p:SessionIndex/text()"s,
              issue_instant: ~x"//saml2p:LogoutRequest/@IssueInstant"s,
              version: ~x"//saml2p:LogoutRequest/@Version"s
            )

          # Validate required fields
          cond do
            is_nil(parsed_request.request_id) or parsed_request.request_id == "" ->
              {:error, "Missing or empty Request ID"}

            is_nil(parsed_request.issuer) or parsed_request.issuer == "" ->
              {:error, "Missing or empty Issuer"}

            true ->
              {:ok,
               %{
                 request_id: parsed_request.request_id,
                 issuer: parsed_request.issuer,
                 destination: parsed_request.destination,
                 name_id: parsed_request.name_id,
                 name_id_format: parsed_request.name_id_format,
                 session_index: parsed_request.session_index,
                 issue_instant: parsed_request.issue_instant,
                 version: parsed_request.version
               }}
          end
        rescue
          error ->
            {:error, "Failed to parse SAML LogoutRequest: #{inspect(error)}"}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  def parse_logout_request(nil), do: {:error, "SAML logout request cannot be empty"}
  def parse_logout_request(""), do: {:error, "SAML logout request cannot be empty"}

  @doc """
  Generate a SAML Response with Assertion, optionally signed.
  """
  def generate_saml_response(
        %Session{} = session,
        %ServiceProvider{} = sp,
        %User{} = user,
        options \\ []
      ) do
    response_id = generate_id()
    assertion_id = generate_id()
    now = DateTime.utc_now()
    # 5 minutes
    expires_at = DateTime.add(now, 300, :second)

    # Build attribute statements
    attributes = build_attribute_statements(user, sp)

    # Get issuer URL
    issuer_url = get_issuer_url()

    saml_response = """
    <?xml version="1.0" encoding="UTF-8"?>
    <saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                     ID="#{response_id}"
                     InResponseTo="#{session.request_id}"
                     IssueInstant="#{DateTime.to_iso8601(now)}"
                     Destination="#{sp.acs_url}"
                     Version="2.0">
      <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">#{issuer_url}</saml2:Issuer>
      <saml2p:Status>
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
      </saml2p:Status>
      <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                       ID="#{assertion_id}"
                       IssueInstant="#{DateTime.to_iso8601(now)}"
                       Version="2.0">
        <saml2:Issuer>#{issuer_url}</saml2:Issuer>
        <saml2:Subject>
          <saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">#{session.subject_id}</saml2:NameID>
          <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml2:SubjectConfirmationData InResponseTo="#{session.request_id}"
                                           NotOnOrAfter="#{DateTime.to_iso8601(expires_at)}"
                                           Recipient="#{sp.acs_url}"/>
          </saml2:SubjectConfirmation>
        </saml2:Subject>
        <saml2:Conditions NotBefore="#{DateTime.to_iso8601(now)}"
                          NotOnOrAfter="#{DateTime.to_iso8601(expires_at)}">
          <saml2:AudienceRestriction>
            <saml2:Audience>#{sp.entity_id}</saml2:Audience>
          </saml2:AudienceRestriction>
        </saml2:Conditions>
        <saml2:AuthnStatement AuthnInstant="#{DateTime.to_iso8601(now)}"
                              SessionIndex="#{session.session_id}">
          <saml2:AuthnContext>
            <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
          </saml2:AuthnContext>
        </saml2:AuthnStatement>#{if attributes != "", do: "\n        #{attributes}", else: ""}
      </saml2:Assertion>
    </saml2p:Response>
    """

    unsigned_response = String.trim(saml_response)

    # Check if signing is requested and certificate is available
    if Keyword.get(options, :sign, false) do
      case get_signing_certificate_struct(sp.organization_id) do
        %Authify.Accounts.Certificate{} = cert ->
          case Authify.SAML.XMLSignature.sign_xml(unsigned_response, cert) do
            {:ok, signed_response} -> {:ok, signed_response}
            {:error, reason} -> {:error, "Failed to sign SAML response: #{reason}"}
          end

        nil ->
          # Return unsigned if no certificate available
          {:ok, unsigned_response}
      end
    else
      {:ok, unsigned_response}
    end
  end

  @doc """
  Generate a SAML LogoutResponse.
  """
  def generate_logout_response(logout_request, %ServiceProvider{} = sp) do
    response_id = generate_id()
    now = DateTime.utc_now()
    issuer_url = get_issuer_url()

    # Determine destination URL - prefer SLS URL, fallback to ACS URL
    destination = sp.sls_url || sp.acs_url

    saml_response = """
    <?xml version="1.0" encoding="UTF-8"?>
    <saml2p:LogoutResponse xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                           ID="#{response_id}"
                           InResponseTo="#{logout_request.request_id}"
                           IssueInstant="#{DateTime.to_iso8601(now)}"
                           Destination="#{destination}"
                           Version="2.0">
      <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">#{issuer_url}</saml2:Issuer>
      <saml2p:Status>
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
      </saml2p:Status>
    </saml2p:LogoutResponse>
    """

    {:ok, String.trim(saml_response)}
  end

  @doc """
  Generate a SAML LogoutRequest (for IdP-initiated logout).
  """
  def generate_logout_request(%Session{} = session, %ServiceProvider{} = sp) do
    request_id = generate_id()
    now = DateTime.utc_now()
    issuer_url = get_issuer_url()

    # Determine destination URL - prefer SLS URL, fallback to ACS URL
    destination = sp.sls_url || sp.acs_url

    saml_request = """
    <?xml version="1.0" encoding="UTF-8"?>
    <saml2p:LogoutRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                          ID="#{request_id}"
                          IssueInstant="#{DateTime.to_iso8601(now)}"
                          Destination="#{destination}"
                          Version="2.0">
      <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">#{issuer_url}</saml2:Issuer>
      <saml2:NameID xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                    Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">#{session.subject_id}</saml2:NameID>
      <saml2p:SessionIndex>#{session.session_id}</saml2p:SessionIndex>
    </saml2p:LogoutRequest>
    """

    {:ok, String.trim(saml_request), request_id}
  end

  @doc """
  Generate SAML IdP metadata XML.
  """
  def generate_metadata(organization) do
    # Use organization-specific issuer URL and endpoints
    issuer_url = get_organization_issuer_url(organization)
    base_url = AuthifyWeb.Endpoint.url()
    org_slug = if organization, do: organization.slug, else: "global"

    # Build organization-scoped endpoint URLs
    sso_url = "#{base_url}/#{org_slug}/saml/sso"
    slo_url = "#{base_url}/#{org_slug}/saml/slo"

    metadata = """
    <?xml version="1.0" encoding="UTF-8"?>
    <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                         entityID="#{issuer_url}">
      <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
          <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:X509Data>
              <ds:X509Certificate>#{get_signing_certificate(organization)}</ds:X509Certificate>
            </ds:X509Data>
          </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                Location="#{sso_url}"/>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                Location="#{sso_url}"/>
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                Location="#{slo_url}"/>
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                Location="#{slo_url}"/>
      </md:IDPSSODescriptor>
    </md:EntityDescriptor>
    """

    {:ok, String.trim(metadata)}
  end

  # Private helper functions

  defp decode_saml_data(data) when is_binary(data) do
    # Try to decode if it looks like Base64
    if String.match?(data, ~r/^[A-Za-z0-9+\/]+=*$/) and String.length(data) > 50 do
      case Base.decode64(data) do
        {:ok, decoded} ->
          if String.contains?(decoded, "<") do
            {:ok, decoded}
          else
            {:error, "Decoded data is not valid XML"}
          end

        :error ->
          {:error, "Invalid Base64 encoding"}
      end
    else
      # Assume it's already XML
      if String.contains?(data, "<") do
        {:ok, data}
      else
        {:error, "Data is neither valid Base64 nor XML"}
      end
    end
  end

  defp build_attribute_statements(%User{} = user, %ServiceProvider{} = sp) do
    attribute_mapping = ServiceProvider.decode_attribute_mapping(sp)

    if Enum.empty?(attribute_mapping) do
      ""
    else
      attribute_elements =
        Enum.map(attribute_mapping, fn {saml_attr, user_field} ->
          value = get_user_attribute(user, user_field)

          if value do
            """
            <saml2:Attribute Name="#{saml_attr}">
              <saml2:AttributeValue>#{Phoenix.HTML.html_escape(value) |> Phoenix.HTML.safe_to_string()}</saml2:AttributeValue>
            </saml2:Attribute>
            """
          else
            nil
          end
        end)
        |> Enum.filter(&(&1 != nil))
        |> Enum.join("\n          ")

      if String.trim(attribute_elements) != "" do
        "\n        <saml2:AttributeStatement>\n          #{attribute_elements}\n        </saml2:AttributeStatement>"
      else
        ""
      end
    end
  end

  defp get_user_attribute(%User{} = user, field) do
    case field do
      "email" -> user.email
      "first_name" -> user.first_name
      "last_name" -> user.last_name
      "{{first_name}} {{last_name}}" -> "#{user.first_name} #{user.last_name}"
      _ -> nil
    end
  end

  defp generate_id do
    "_" <> (:crypto.strong_rand_bytes(20) |> Base.hex_encode32(case: :lower))
  end

  defp get_issuer_url do
    # This is the IdP's entity ID (legacy, not organization-scoped)
    AuthifyWeb.Endpoint.url() <> "/saml/metadata"
  end

  defp get_organization_issuer_url(organization) when is_nil(organization) do
    # Fallback for global/legacy
    get_issuer_url()
  end

  defp get_organization_issuer_url(organization) do
    # Organization-specific entity ID
    AuthifyWeb.Endpoint.url() <> "/#{organization.slug}/saml/metadata"
  end

  defp get_signing_certificate(organization) when is_nil(organization) do
    "NO_SAML_SIGNING_CERTIFICATE_CONFIGURED_PLEASE_GENERATE_OR_UPLOAD_ONE"
  end

  defp get_signing_certificate(organization) do
    case Authify.Accounts.get_active_saml_signing_certificate(organization) do
      %Authify.Accounts.Certificate{} = cert ->
        Authify.Accounts.Certificate.certificate_data(cert)

      nil ->
        # Return a placeholder indicating no certificate is configured
        "NO_SAML_SIGNING_CERTIFICATE_CONFIGURED_PLEASE_GENERATE_OR_UPLOAD_ONE"
    end
  end

  defp get_signing_certificate_struct(organization_id) do
    organization = %Authify.Accounts.Organization{id: organization_id}
    Authify.Accounts.get_active_saml_signing_certificate(organization)
  end
end
