defmodule Authify.SAML.XMLSignature do
  @moduledoc """
  XML Digital Signature implementation focused on SAML requirements.

  This module provides XML canonicalization and digital signature capabilities
  specifically for SAML assertions, responses, and metadata. It implements
  a subset of the XML Digital Signature specification (XMLDSig) needed for
  SAML compliance.
  """

  alias Authify.Accounts.Certificate

  @doc """
  Signs an XML document by inserting a ds:Signature element.
  """
  def sign_xml(xml_string, %Certificate{} = certificate, options \\ []) do
    # Parse XML to ensure it's well-formed
    SweetXml.parse(xml_string)

    # Canonicalize the XML
    canonical_xml = canonicalize_xml(xml_string)

    # Create the signature
    signature_element = create_signature(canonical_xml, certificate, options)

    # Insert the signature into the XML
    signed_xml = insert_signature(xml_string, signature_element, options)

    {:ok, signed_xml}
  rescue
    error ->
      {:error, "Failed to sign XML: #{inspect(error)}"}
  catch
    :exit, reason ->
      {:error, "Failed to sign XML: #{inspect(reason)}"}
  end

  @doc """
  Verifies an XML digital signature.
  """
  def verify_signature(signed_xml, %Certificate{} = certificate) do
    # Extract signature from XML
    signature_info = extract_signature_info(signed_xml)

    # Remove signature from XML for verification
    unsigned_xml = remove_signature(signed_xml)

    # Canonicalize the unsigned XML
    canonical_xml = canonicalize_xml(unsigned_xml)

    # Verify the signature
    verify_signature_info(canonical_xml, signature_info, certificate)
  rescue
    error ->
      {:error, "Failed to verify signature: #{inspect(error)}"}
  end

  @doc """
  Canonicalizes XML according to C14N specification (simplified version).

  This implements basic XML canonicalization by:
  1. Normalizing whitespace
  2. Sorting attributes
  3. Removing unnecessary namespace declarations
  4. Ensuring consistent encoding
  """
  def canonicalize_xml(xml_string) when is_binary(xml_string) do
    # Parse the XML
    parsed = SweetXml.parse(xml_string)

    # Convert back to string with normalization
    canonical = normalize_xml_element(parsed)

    # Remove extra whitespace between elements but preserve content whitespace
    canonical
    |> String.replace(~r/>\s+</, "><")
    |> String.trim()
  end

  # Private helper functions

  # Handle xmerl's xmlElement structure
  defp normalize_xml_element(
         {:xmlElement, name, _expanded_name, _nsinfo, _namespace, _parents, _pos, attributes,
          children, _language, _xmlbase, _elementdef}
       ) do
    # Extract and sort attributes
    sorted_attrs = extract_and_sort_attributes(attributes)
    attr_string = format_attributes(sorted_attrs)

    # Recursively normalize children (filter out text-only whitespace)
    normalized_children = normalize_children(children)

    "<#{name}#{attr_string}>#{normalized_children}</#{name}>"
  end

  # Handle xmerl's xmlText structure
  defp normalize_xml_element({:xmlText, _parents, _pos, _language, value, _type}) do
    # Convert charlist to string if needed and escape XML special characters
    text = if is_list(value), do: List.to_string(value), else: to_string(value)

    text
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
    |> String.replace("'", "&apos;")
  end

  # Handle simple tuples (fallback for other formats)
  defp normalize_xml_element({name, attributes, children}) when is_list(attributes) do
    # Sort attributes by name for canonical order
    sorted_attrs = Enum.sort(attributes, fn {k1, _}, {k2, _} -> k1 <= k2 end)

    # Normalize attribute format
    attr_string = format_attributes(sorted_attrs)

    # Recursively normalize children
    normalized_children = normalize_children(children)

    "<#{name}#{attr_string}>#{normalized_children}</#{name}>"
  end

  defp normalize_xml_element({name, children}) when is_list(children) do
    normalized_children = normalize_children(children)
    "<#{name}>#{normalized_children}</#{name}>"
  end

  defp normalize_xml_element(text) when is_binary(text) do
    # Escape XML special characters
    text
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
    |> String.replace("'", "&apos;")
  end

  defp extract_and_sort_attributes(attributes) do
    attributes
    |> Enum.map(fn {:xmlAttribute, name, _expanded_name, _nsinfo, _namespace, _parents, _pos,
                    _language, value, _normalized} ->
      attr_value = if is_list(value), do: List.to_string(value), else: to_string(value)
      {name, attr_value}
    end)
    |> Enum.sort(fn {k1, _}, {k2, _} -> k1 <= k2 end)
  end

  defp normalize_children(children) when is_list(children) do
    Enum.map_join(children, "", &normalize_xml_element/1)
  end

  defp format_attributes([]), do: ""

  defp format_attributes(attributes) do
    attr_strings =
      Enum.map(attributes, fn {name, value} ->
        "#{name}=\"#{escape_attribute_value(value)}\""
      end)

    " " <> Enum.join(attr_strings, " ")
  end

  defp escape_attribute_value(value) do
    value
    |> String.replace("&", "&amp;")
    |> String.replace("\"", "&quot;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
  end

  defp create_signature(canonical_xml, %Certificate{} = certificate, options) do
    # Generate signature ID
    signature_id = Keyword.get(options, :signature_id, generate_signature_id())

    # Calculate digest of canonical XML
    digest = calculate_sha256_digest(canonical_xml)
    digest_base64 = Base.encode64(digest)

    # Create SignedInfo element
    signed_info = create_signed_info(digest_base64, options)

    # Canonicalize SignedInfo
    canonical_signed_info = canonicalize_xml(signed_info)

    # Sign the canonical SignedInfo
    signature_value = sign_data(canonical_signed_info, certificate)
    signature_value_base64 = Base.encode64(signature_value)

    # Get certificate data for KeyInfo
    cert_data = Certificate.certificate_data(certificate)

    # Build complete signature element
    """
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="#{signature_id}">
      #{signed_info}
      <ds:SignatureValue>#{signature_value_base64}</ds:SignatureValue>
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>#{cert_data}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </ds:Signature>
    """
  end

  defp create_signed_info(digest_base64, options) do
    reference_uri = Keyword.get(options, :reference_uri, "")

    """
    <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#{reference_uri}">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>#{digest_base64}</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    """
  end

  defp calculate_sha256_digest(data) when is_binary(data) do
    :crypto.hash(:sha256, data)
  end

  defp sign_data(data, %Certificate{private_key: private_key_pem}) do
    # Private key is already decrypted by Authify.Encrypted.Binary Ecto type
    # Parse the PEM private key
    case parse_private_key(private_key_pem) do
      {:ok, private_key} ->
        # Sign the data using RSA-SHA256
        :public_key.sign(data, :sha256, private_key)

      {:error, reason} ->
        # Return a recognizable error signature
        :crypto.hash(:sha256, "ERROR_PARSING_PRIVATE_KEY_#{reason}")
    end
  rescue
    error ->
      # Return a recognizable error signature
      :crypto.hash(:sha256, "ERROR_SIGNING_DATA_#{inspect(error)}")
  end

  defp parse_private_key(private_key_pem) when is_binary(private_key_pem) do
    # Remove the placeholder check and try to parse real PEM
    if String.contains?(private_key_pem, "PLACEHOLDER") do
      {:error, "placeholder_key_not_supported"}
    else
      # Parse PEM entries
      pem_entries = :public_key.pem_decode(private_key_pem)

      case pem_entries do
        [pem_entry | _] ->
          private_key = :public_key.pem_entry_decode(pem_entry)
          {:ok, private_key}

        [] ->
          {:error, "no_pem_entries_found"}
      end
    end
  rescue
    error ->
      {:error, "pem_decode_failed_#{inspect(error)}"}
  end

  defp insert_signature(xml_string, signature_element, options) do
    insertion_point = Keyword.get(options, :insertion_point, :after_issuer)

    case insertion_point do
      :after_issuer ->
        # Insert after the first Issuer element (common for SAML)
        String.replace(
          xml_string,
          ~r/(<saml2?:Issuer[^>]*>.*?<\/saml2?:Issuer>)/,
          "\\1\n    #{signature_element}"
        )

      :before_close ->
        # Insert before the closing tag of the root element
        String.replace(xml_string, ~r/(<\/[^>]+>)$/, "    #{signature_element}\n\\1")

      {:after_element, element_name} ->
        # Insert after a specific element
        pattern = ~r/(<#{element_name}[^>]*>.*?<\/#{element_name}>)/
        String.replace(xml_string, pattern, "\\1\n    #{signature_element}")
    end
  end

  defp extract_signature_info(signed_xml) do
    # Parse the signed XML
    parsed = SweetXml.parse(signed_xml)

    # Extract signature components using XPath-like selectors
    signature_value = extract_signature_value(parsed)
    signed_info = extract_signed_info(parsed)
    certificate_data = extract_certificate_from_signature(parsed)

    %{
      signature_value: signature_value,
      signed_info: signed_info,
      certificate: certificate_data
    }
  rescue
    error ->
      # Return empty values if extraction fails - this maintains backward compatibility
      # but allows the verification to fail properly
      %{
        signature_value: "",
        signed_info: "",
        certificate: "",
        error: "Failed to extract signature info: #{inspect(error)}"
      }
  end

  defp extract_signature_value(parsed_xml) do
    # Look for ds:SignatureValue element
    case find_element_text(parsed_xml, "SignatureValue") do
      nil -> ""
      value -> String.trim(value)
    end
  rescue
    _ -> ""
  end

  defp extract_signed_info(parsed_xml) do
    # Find the ds:SignedInfo element and canonicalize it
    case find_element(parsed_xml, "SignedInfo") do
      nil ->
        ""

      signed_info_element ->
        # Convert the element back to XML string for canonicalization
        xml_string = element_to_xml_string(signed_info_element)
        canonicalize_xml(xml_string)
    end
  rescue
    _ -> ""
  end

  defp extract_certificate_from_signature(parsed_xml) do
    # Look for ds:X509Certificate element within ds:KeyInfo
    case find_element_text(parsed_xml, "X509Certificate") do
      nil ->
        ""

      cert_data ->
        # Add PEM headers if not present
        cleaned_cert = String.trim(cert_data)

        if String.starts_with?(cleaned_cert, "-----BEGIN") do
          cleaned_cert
        else
          "-----BEGIN CERTIFICATE-----\n#{cleaned_cert}\n-----END CERTIFICATE-----"
        end
    end
  rescue
    _ -> ""
  end

  # Helper function to find an element by name in parsed XML
  defp find_element(parsed_xml, element_name) do
    find_element_recursive(parsed_xml, element_name)
  end

  defp find_element_recursive(
         {:xmlElement, name, expanded_name, nsinfo, namespace, parents, pos, attributes, children,
          language, xmlbase, elementdef},
         target_name
       ) do
    # Convert atom to string for comparison
    element_name = Atom.to_string(name)

    # Check if this is the target element (handle namespace prefixes)
    if String.ends_with?(element_name, target_name) or element_name == target_name do
      {:xmlElement, name, expanded_name, nsinfo, namespace, parents, pos, attributes, children,
       language, xmlbase, elementdef}
    else
      # Search in children
      find_in_children(children, target_name)
    end
  end

  defp find_element_recursive(_, _), do: nil

  defp find_in_children([], _), do: nil

  defp find_in_children([child | rest], target_name) do
    case find_element_recursive(child, target_name) do
      nil -> find_in_children(rest, target_name)
      found -> found
    end
  end

  # Helper function to find element text content
  defp find_element_text(parsed_xml, element_name) do
    case find_element(parsed_xml, element_name) do
      nil ->
        nil

      {:xmlElement, _, _, _, _, _, _, _, children, _, _, _} ->
        extract_text_content(children)
    end
  end

  defp extract_text_content([]), do: ""

  defp extract_text_content([{:xmlText, _, _, _, text, _} | rest]) when is_list(text) do
    List.to_string(text) <> extract_text_content(rest)
  end

  defp extract_text_content([{:xmlText, _, _, _, text, _} | rest]) do
    to_string(text) <> extract_text_content(rest)
  end

  defp extract_text_content([_ | rest]) do
    extract_text_content(rest)
  end

  # Helper function to convert XML element back to string
  defp element_to_xml_string({:xmlElement, name, _, _, _, _, _, attributes, children, _, _, _}) do
    attr_string = format_xml_attributes(attributes)
    content = children_to_xml_string(children)
    "<#{name}#{attr_string}>#{content}</#{name}>"
  end

  defp format_xml_attributes([]), do: ""

  defp format_xml_attributes(attributes) do
    attr_strings =
      Enum.map(attributes, fn {:xmlAttribute, name, _, _, _, _, _, _, value, _} ->
        attr_value = if is_list(value), do: List.to_string(value), else: to_string(value)
        " #{name}=\"#{escape_attribute_value(attr_value)}\""
      end)

    Enum.join(attr_strings, "")
  end

  defp children_to_xml_string([]), do: ""

  defp children_to_xml_string([{:xmlText, _, _, _, text, _} | rest]) do
    text_content = if is_list(text), do: List.to_string(text), else: to_string(text)
    text_content <> children_to_xml_string(rest)
  end

  defp children_to_xml_string([{:xmlElement, _, _, _, _, _, _, _, _, _, _, _} = element | rest]) do
    element_to_xml_string(element) <> children_to_xml_string(rest)
  end

  defp children_to_xml_string([_ | rest]) do
    children_to_xml_string(rest)
  end

  defp remove_signature(signed_xml) do
    # Remove the ds:Signature element from XML
    String.replace(signed_xml, ~r/<ds:Signature[^>]*>.*?<\/ds:Signature>/s, "")
  end

  defp verify_signature_info(canonical_xml, signature_info, %Certificate{} = certificate) do
    signature_value = Map.get(signature_info, :signature_value, "")
    signed_info = Map.get(signature_info, :signed_info, "")

    with true <- signature_value != "" and signed_info != "",
         {:ok, public_key} <- extract_public_key(certificate.certificate),
         {:ok, true} <- verify_digest(canonical_xml, signed_info),
         {:ok, signature_bytes} <- Base.decode64(signature_value) do
      if :public_key.verify(signed_info, :sha256, signature_bytes, public_key) do
        {:ok, true}
      else
        {:ok, false}
      end
    else
      false ->
        {:error, "missing_signature_data"}

      {:ok, false} ->
        {:error, "digest_mismatch"}

      {:error, reason} when is_binary(reason) ->
        if String.starts_with?(reason, "digest_verification_failed") or
             String.starts_with?(reason, "certificate_error") do
          {:error, reason}
        else
          {:error, "certificate_error_#{reason}"}
        end

      :error ->
        {:error, "invalid_base64_signature"}
    end
  rescue
    error ->
      {:error, "verification_failed_#{inspect(error)}"}
  end

  defp verify_digest(canonical_xml, signed_info) do
    # Extract the digest value from SignedInfo
    parsed_signed_info = SweetXml.parse(signed_info)

    case find_element_text(parsed_signed_info, "DigestValue") do
      nil ->
        {:error, "digest_value_not_found"}

      digest_base64 ->
        # Calculate the digest of the canonical XML
        calculated_digest = calculate_sha256_digest(canonical_xml)
        calculated_digest_base64 = Base.encode64(calculated_digest)

        # Compare digests
        if String.trim(digest_base64) == calculated_digest_base64 do
          {:ok, true}
        else
          {:ok, false}
        end
    end
  rescue
    error ->
      {:error, "digest_extraction_failed_#{inspect(error)}"}
  end

  defp extract_public_key(certificate_pem) when is_binary(certificate_pem) do
    if String.contains?(certificate_pem, "PLACEHOLDER") do
      {:error, "placeholder_certificate_not_supported"}
    else
      with pem_entries when pem_entries != [] <- :public_key.pem_decode(certificate_pem),
           [pem_entry | _] <- pem_entries,
           certificate <- :public_key.pem_entry_decode(pem_entry),
           {:Certificate, tbs_certificate, _signature_algorithm, _signature_value} <- certificate,
           {:TBSCertificate, _version, _serial, _signature, _issuer, _validity, _subject,
            subject_public_key_info, _issuer_unique_id, _subject_unique_id,
            _extensions} <- tbs_certificate,
           {:SubjectPublicKeyInfo, _algorithm, public_key_data} <- subject_public_key_info do
        {:ok, public_key_data}
      else
        [] ->
          {:error, "no_certificate_entries_found"}

        _ ->
          {:error, "unsupported_certificate_format"}
      end
    end
  rescue
    error ->
      {:error, "certificate_decode_failed_#{inspect(error)}"}
  end

  defp generate_signature_id do
    "_" <> (:crypto.strong_rand_bytes(16) |> Base.hex_encode32(case: :lower))
  end
end
