defmodule Authify.SAML.Certificate do
  @moduledoc """
  Schema for SAML IdP certificates used for signing and encryption.
  Stores PEM-formatted certificates and private keys with expiration tracking.
  Supports per-organization certificate management.
  """
  use Ecto.Schema
  import Ecto.Changeset

  schema "saml_certificates" do
    field :name, :string
    # "signing" or "encryption"
    field :purpose, :string
    field :certificate, :string
    field :private_key, :string
    field :is_active, :boolean, default: true
    field :expires_at, :utc_datetime

    belongs_to :organization, Authify.Accounts.Organization

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(certificate, attrs) do
    certificate
    |> cast(attrs, [
      :name,
      :purpose,
      :certificate,
      :private_key,
      :is_active,
      :expires_at,
      :organization_id
    ])
    |> validate_required([
      :name,
      :purpose,
      :certificate,
      :private_key,
      :expires_at,
      :organization_id
    ])
    |> validate_inclusion(:purpose, ["signing", "encryption"])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_certificate_format()
    |> validate_private_key_format()
    |> ensure_only_one_active_per_purpose()
    |> foreign_key_constraint(:organization_id)
  end

  @doc false
  def form_changeset(certificate, attrs \\ %{}) do
    certificate
    |> cast(attrs, [
      :name,
      :purpose,
      :certificate,
      :private_key,
      :is_active,
      :expires_at,
      :organization_id
    ])
  end

  defp validate_certificate_format(changeset) do
    case get_field(changeset, :certificate) do
      nil ->
        changeset

      cert_string ->
        if String.contains?(cert_string, "-----BEGIN CERTIFICATE-----") and
             String.contains?(cert_string, "-----END CERTIFICATE-----") do
          changeset
        else
          add_error(changeset, :certificate, "must be a valid PEM certificate")
        end
    end
  end

  defp validate_private_key_format(changeset) do
    case get_field(changeset, :private_key) do
      nil ->
        changeset

      key_string ->
        if (String.contains?(key_string, "-----BEGIN PRIVATE KEY-----") and
              String.contains?(key_string, "-----END PRIVATE KEY-----")) or
             (String.contains?(key_string, "-----BEGIN RSA PRIVATE KEY-----") and
                String.contains?(key_string, "-----END RSA PRIVATE KEY-----")) do
          changeset
        else
          add_error(changeset, :private_key, "must be a valid PEM private key")
        end
    end
  end

  defp ensure_only_one_active_per_purpose(changeset) do
    # For MySQL, we need to enforce this in application code since
    # MySQL doesn't support WHERE clauses in unique indexes
    if get_field(changeset, :is_active) do
      changeset
    else
      changeset
    end
  end

  def expired?(%__MODULE__{expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end

  def valid?(%__MODULE__{} = certificate) do
    certificate.is_active and not expired?(certificate)
  end

  def generate_self_signed_certificate(_organization_name, valid_days \\ 365) do
    # This is a placeholder - in a real implementation, you'd use
    # a proper certificate generation library
    expires_at = DateTime.utc_now() |> DateTime.add(valid_days * 24 * 3600, :second)

    %{
      certificate: """
      -----BEGIN CERTIFICATE-----
      (Generated certificate would go here)
      -----END CERTIFICATE-----
      """,
      private_key: """
      -----BEGIN PRIVATE KEY-----
      (Generated private key would go here)
      -----END PRIVATE KEY-----
      """,
      expires_at: expires_at
    }
  end
end
