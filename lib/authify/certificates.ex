defmodule Authify.Certificates do
  @moduledoc """
  Context for managing certificates.
  """

  import Ecto.Query, warn: false
  import Ecto.Changeset, only: [get_change: 2, get_field: 2]

  alias Authify.Accounts.{Certificate, Organization}
  alias Authify.Repo

  @doc """
  Returns the list of certificates for an organization.
  """
  def list_certificates(%Organization{id: org_id}) do
    from(c in Certificate,
      where: c.organization_id == ^org_id and is_nil(c.deleted_at),
      order_by: [desc: c.inserted_at]
    )
    |> Repo.all()
  end

  @doc """
  Gets a single certificate.
  """
  def get_certificate!(id) do
    Repo.one!(from c in Certificate, where: c.id == ^id and is_nil(c.deleted_at))
  end

  @doc """
  Creates a certificate.
  """
  def create_certificate(%Organization{} = organization, attrs \\ %{}) do
    attrs = Map.put(attrs, "organization_id", organization.id)

    changeset =
      %Certificate{}
      |> Certificate.changeset(attrs)

    # If creating an active certificate, deactivate existing active certificates of same usage
    if get_change(changeset, :is_active) == true do
      usage = get_field(changeset, :usage)
      deactivate_existing_active_certificates(organization.id, usage)
    end

    Repo.insert(changeset)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking certificate changes.
  """
  def change_certificate(%Certificate{} = certificate, attrs \\ %{}) do
    Certificate.changeset(certificate, attrs)
  end

  @doc """
  Generates a self-signed certificate with specified usage.
  """
  def generate_certificate(%Organization{} = organization, attrs \\ %{}) do
    usage = Map.get(attrs, "usage", "saml_signing")

    # Create self-signed certificate
    validity_days = Map.get(attrs, "validity_days", 365)

    # Create subject based on usage type
    usage_label =
      case usage do
        "saml_signing" -> "SAML Signing"
        "saml_encryption" -> "SAML Encryption"
        "oauth_signing" -> "OAuth Signing"
        "audit_signing" -> "Audit Signing"
        _ -> "Certificate"
      end

    subject = "/CN=#{organization.name} #{usage_label}/O=#{organization.name}"

    {private_key_pem, certificate_pem} =
      create_self_signed_certificate(nil, subject, validity_days)

    # Default certificate name based on usage
    default_name =
      case usage do
        "saml_signing" -> "SAML Signing Certificate"
        "saml_encryption" -> "SAML Encryption Certificate"
        "oauth_signing" -> "OAuth Signing Certificate"
        "audit_signing" -> "Audit Signing Certificate"
        _ -> "Certificate"
      end

    # Note: private_key is automatically encrypted by Authify.Encrypted.Binary Ecto type
    certificate_attrs = %{
      "name" => Map.get(attrs, "name", default_name),
      "usage" => usage,
      "private_key" => private_key_pem,
      "certificate" => certificate_pem,
      "expires_at" => DateTime.add(DateTime.utc_now(), validity_days, :day),
      "is_active" => Map.get(attrs, "is_active", false)
    }

    create_certificate(organization, certificate_attrs)
  end

  @doc """
  Generates a SAML signing certificate (alias for compatibility).
  """
  def generate_saml_signing_certificate(organization, attrs \\ %{}) do
    attrs = Map.put(attrs, "usage", "saml_signing")
    generate_certificate(organization, attrs)
  end

  @doc """
  Gets a certificate with organization verification.
  """
  def get_certificate!(id, organization, opts \\ []) do
    include_deleted = Keyword.get(opts, :include_deleted, false)

    certificate =
      if include_deleted do
        Repo.get!(Certificate, id)
      else
        Repo.one!(from c in Certificate, where: c.id == ^id and is_nil(c.deleted_at))
      end

    if certificate.organization_id == organization.id do
      certificate
    else
      raise Ecto.NoResultsError, queryable: Certificate
    end
  end

  @doc """
  Gets a certificate's private key.

  The private key is automatically decrypted by the Authify.Encrypted.Binary Ecto type,
  so this function simply returns it wrapped in {:ok, ...} for API compatibility.

  Returns `{:ok, private_key}` on success.
  """
  def decrypt_certificate_private_key(%Certificate{private_key: private_key}) do
    {:ok, private_key}
  end

  @doc """
  Updates a certificate.
  """
  def update_certificate(certificate, attrs) do
    changeset =
      certificate
      |> Certificate.changeset(attrs)

    # If updating to active, deactivate existing active certificates of same usage
    if get_change(changeset, :is_active) == true do
      usage = get_field(changeset, :usage)
      organization_id = get_field(changeset, :organization_id)
      deactivate_existing_active_certificates(organization_id, usage, certificate.id)
    end

    Repo.update(changeset)
  end

  @doc """
  Deletes a certificate.
  """
  def delete_certificate(certificate) do
    certificate
    |> Ecto.Changeset.change(deleted_at: DateTime.utc_now() |> DateTime.truncate(:second))
    |> Repo.update()
  end

  @doc """
  Gets the active SAML signing certificate for an organization.
  """
  def get_active_saml_signing_certificate(organization) do
    from(c in Certificate,
      where:
        c.organization_id == ^organization.id and c.usage == "saml_signing" and
          c.is_active == true and is_nil(c.deleted_at),
      limit: 1
    )
    |> Repo.one()
  end

  @doc """
  Gets the active OAuth signing certificate for an organization.
  """
  def get_active_oauth_signing_certificate(organization) do
    from(c in Certificate,
      where:
        c.organization_id == ^organization.id and c.usage == "oauth_signing" and
          c.is_active == true and is_nil(c.deleted_at),
      limit: 1
    )
    |> Repo.one()
  end

  @doc """
  Gets the active OAuth signing certificate, auto-generating one if none exists.
  """
  def get_or_generate_oauth_signing_certificate(organization) do
    case get_active_oauth_signing_certificate(organization) do
      nil ->
        generate_certificate(organization, %{
          "usage" => "oauth_signing",
          "is_active" => true,
          "validity_days" => 365
        })

      cert ->
        {:ok, cert}
    end
  end

  @doc """
  Gets the active audit signing certificate for an organization by org ID.
  """
  def get_active_audit_signing_certificate(org_id) when is_integer(org_id) do
    from(c in Certificate,
      where:
        c.organization_id == ^org_id and c.usage == "audit_signing" and
          c.is_active == true and is_nil(c.deleted_at),
      limit: 1
    )
    |> Repo.one()
  end

  @doc """
  Gets the active audit signing certificate, auto-generating one if none exists.
  """
  def get_or_generate_audit_signing_certificate(org_id) when is_integer(org_id) do
    case get_active_audit_signing_certificate(org_id) do
      nil ->
        organization = Repo.get!(Organization, org_id)

        result =
          generate_certificate(organization, %{
            "usage" => "audit_signing",
            "is_active" => true,
            "validity_days" => 365
          })

        if match?({:ok, _}, result), do: Authify.AuditLog.KeyCache.invalidate(org_id)

        result

      cert ->
        {:ok, cert}
    end
  end

  defp create_self_signed_certificate(_private_key, subject, validity_days) do
    # Generate RSA private key using X509 library
    private_key = X509.PrivateKey.new_rsa(2048)

    # Create self-signed certificate
    certificate =
      X509.Certificate.self_signed(
        private_key,
        subject,
        validity: validity_days
      )

    # Convert to PEM format
    private_key_pem = X509.PrivateKey.to_pem(private_key)
    certificate_pem = X509.Certificate.to_pem(certificate)

    {String.trim(private_key_pem), String.trim(certificate_pem)}
  rescue
    error ->
      # Fallback to placeholder if certificate generation fails
      private_key_pem = """
      -----BEGIN RSA PRIVATE KEY-----
      PLACEHOLDER_PRIVATE_KEY_DATA_ERROR_#{inspect(error)}
      -----END RSA PRIVATE KEY-----
      """

      certificate_pem = """
      -----BEGIN CERTIFICATE-----
      PLACEHOLDER_CERTIFICATE_DATA_ERROR_#{inspect(error)}
      -----END CERTIFICATE-----
      """

      {String.trim(private_key_pem), String.trim(certificate_pem)}
  end

  # Private helper functions for certificate management

  defp deactivate_existing_active_certificates(organization_id, usage, exclude_id \\ nil) do
    query =
      from(c in Certificate,
        where: c.organization_id == ^organization_id and c.usage == ^usage and c.is_active == true
      )

    query =
      if exclude_id do
        from(c in query, where: c.id != ^exclude_id)
      else
        query
      end

    query
    |> Repo.update_all(set: [is_active: false])
  end
end
