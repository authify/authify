defmodule AuthifyWeb.CertificatesHTML do
  use AuthifyWeb, :html

  embed_templates "certificates_html/*"

  @doc """
  Returns the appropriate badge class for certificate status.
  """
  def certificate_status_badge(%{is_active: true, expires_at: expires_at}) do
    case DateTime.compare(DateTime.utc_now(), expires_at) do
      :lt -> {"Active", "bg-success"}
      _ -> {"Expired", "bg-danger"}
    end
  end

  def certificate_status_badge(%{is_active: false}) do
    {"Inactive", "bg-secondary"}
  end

  @doc """
  Formats certificate expiration date with appropriate styling.
  """
  def format_expiration(expires_at) do
    case DateTime.compare(DateTime.utc_now(), expires_at) do
      :lt ->
        days_until_expiry = DateTime.diff(expires_at, DateTime.utc_now(), :day)

        cond do
          days_until_expiry <= 7 -> {"text-danger", "Expires soon"}
          days_until_expiry <= 30 -> {"text-warning", "Expires within 30 days"}
          true -> {"text-muted", ""}
        end

      _ ->
        {"text-danger", "Expired"}
    end
  end

  @doc """
  Truncates certificate/key content for display.
  """
  def truncate_pem(pem_content, lines \\ 3) do
    lines_list = String.split(pem_content, "\n")

    if length(lines_list) <= lines do
      pem_content
    else
      truncated_lines = Enum.take(lines_list, lines)
      Enum.join(truncated_lines, "\n") <> "\n... (truncated)"
    end
  end

  @doc """
  Returns certificate usage options for forms.
  """
  def usage_options do
    [
      {"SAML Signing", "saml_signing"},
      {"SAML Encryption", "saml_encryption"},
      {"OAuth Signing", "oauth_signing"}
    ]
  end

  @doc """
  Calculates certificate fingerprints (SHA-1 and SHA-256).
  """
  def certificate_fingerprints(certificate_pem) do
    try do
      # Parse PEM certificate
      pem_entries = :public_key.pem_decode(certificate_pem)

      case pem_entries do
        [pem_entry | _] ->
          # Get the DER-encoded certificate
          {:Certificate, cert_der, :not_encrypted} = pem_entry

          # Calculate fingerprints
          sha1_hash = :crypto.hash(:sha, cert_der)
          sha256_hash = :crypto.hash(:sha256, cert_der)

          %{
            sha1: format_fingerprint(sha1_hash),
            sha256: format_fingerprint(sha256_hash)
          }

        [] ->
          %{sha1: "Invalid certificate", sha256: "Invalid certificate"}
      end
    rescue
      _ ->
        %{sha1: "Invalid certificate", sha256: "Invalid certificate"}
    end
  end

  # Formats a binary hash as a colon-separated hex fingerprint.
  defp format_fingerprint(hash_binary) do
    hash_binary
    |> Base.encode16(case: :upper)
    |> String.graphemes()
    |> Enum.chunk_every(2)
    |> Enum.map(&Enum.join/1)
    |> Enum.join(":")
  end
end
