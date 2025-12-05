defmodule Authify.Accounts.Certificate do
  @moduledoc """
  Schema for X.509 certificates used by the identity provider for SAML and OAuth
  signing and encryption. Supports RSA key pairs with automatic expiration date
  extraction and key pair validation.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias Authify.Accounts.Organization

  @valid_usages ["saml_signing", "saml_encryption", "oauth_signing"]

  @derive {Jason.Encoder, except: [:__meta__, :organization, :private_key]}
  schema "certificates" do
    field :name, :string
    field :usage, :string
    field :private_key, Authify.Encrypted.Binary
    field :certificate, :string
    field :expires_at, :utc_datetime
    field :is_active, :boolean, default: false

    belongs_to :organization, Organization

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(certificate, attrs) do
    certificate
    |> cast(attrs, [
      :name,
      :usage,
      :private_key,
      :certificate,
      :expires_at,
      :is_active,
      :organization_id
    ])
    |> validate_required([:name, :usage, :private_key, :certificate, :organization_id])
    |> validate_inclusion(:usage, @valid_usages)
    |> validate_certificate_format()
    |> validate_private_key_format()
    |> auto_extract_expiration_date()
    |> validate_required([:expires_at])
    |> unique_constraint([:name, :organization_id],
      name: :certificates_name_organization_id_index
    )
  end

  @doc """
  Returns the list of valid certificate usages.
  """
  def valid_usages, do: @valid_usages

  @doc """
  Checks if the certificate is currently valid (active and not expired).
  """
  def valid?(%__MODULE__{is_active: false}), do: false

  def valid?(%__MODULE__{expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :lt
  end

  @doc """
  Extracts the certificate in PEM format without headers/footers for XML inclusion.
  """
  def certificate_data(%__MODULE__{certificate: cert}) do
    cert
    |> String.replace("-----BEGIN CERTIFICATE-----", "")
    |> String.replace("-----END CERTIFICATE-----", "")
    |> String.replace(~r/\s/, "")
  end

  @doc """
  Checks if user is permitted to access a specific certificate.
  """
  def accessible_by_user?(
        %__MODULE__{organization_id: org_id},
        %Authify.Accounts.User{} = user,
        required_role \\ "admin"
      ) do
    case Authify.Accounts.get_user_organization(user.id, org_id) do
      nil ->
        false

      user_org ->
        user_org.active && Authify.Accounts.User.role_permits?(user, required_role, org_id)
    end
  end

  @doc """
  Extracts the expiration date from an X.509 certificate in PEM format.
  """
  def extract_expiration_date(certificate_pem) when is_binary(certificate_pem) do
    with {:ok, certificate} <- parse_certificate_pem(certificate_pem),
         {:ok, {_not_before, not_after}} <- extract_validity_from_certificate(certificate) do
      {:ok, not_after}
    end
  rescue
    error ->
      {:error, "Failed to extract expiration date: #{inspect(error)}"}
  end

  @doc """
  Validates that a private key matches its certificate.
  """
  def validate_key_pair(private_key_pem, certificate_pem)
      when is_binary(private_key_pem) and is_binary(certificate_pem) do
    with {:ok, private_key} <- parse_private_key_pem(private_key_pem),
         {:ok, certificate} <- parse_certificate_pem(certificate_pem),
         {:ok, cert_public_key} <- extract_public_key_from_certificate(certificate),
         {:ok, derived_public_key} <- derive_public_key_from_private(private_key) do
      if public_keys_match?(cert_public_key, derived_public_key) do
        {:ok, true}
      else
        {:error, "Private key does not match certificate"}
      end
    end
  rescue
    error ->
      {:error, "Key pair validation failed: #{inspect(error)}"}
  end

  # Private helper functions for key management

  defp parse_private_key_pem(private_key_pem) do
    pem_entries = :public_key.pem_decode(private_key_pem)

    case pem_entries do
      [pem_entry | _] ->
        private_key = :public_key.pem_entry_decode(pem_entry)
        {:ok, private_key}

      [] ->
        {:error, "No PEM entries found"}
    end
  rescue
    error ->
      {:error, "PEM decode failed: #{inspect(error)}"}
  end

  defp parse_certificate_pem(certificate_pem) do
    pem_entries = :public_key.pem_decode(certificate_pem)

    case pem_entries do
      [pem_entry | _] ->
        certificate = :public_key.pem_entry_decode(pem_entry)
        {:ok, certificate}

      [] ->
        {:error, "No PEM entries found"}
    end
  rescue
    error ->
      {:error, "PEM decode failed: #{inspect(error)}"}
  end

  defp extract_public_key_from_certificate(certificate) do
    case certificate do
      {:Certificate, tbs_certificate, _signature_algorithm, _signature_value} ->
        {:TBSCertificate, _version, _serial, _signature, _issuer, _validity, _subject,
         subject_public_key_info, _issuer_unique_id, _subject_unique_id, _extensions} =
          tbs_certificate

        {:SubjectPublicKeyInfo, _algorithm, public_key_data} = subject_public_key_info

        # Decode the DER-encoded public key data into an RSA public key
        case :public_key.der_decode(:RSAPublicKey, public_key_data) do
          {:RSAPublicKey, _modulus, _exponent} = public_key ->
            {:ok, public_key}

          _ ->
            {:error, "Unable to decode RSA public key from certificate"}
        end

      _ ->
        {:error, "Unsupported certificate format"}
    end
  rescue
    error ->
      {:error, "Failed to extract public key: #{inspect(error)}"}
  end

  defp extract_validity_from_certificate(certificate) do
    case certificate do
      {:Certificate, tbs_certificate, _signature_algorithm, _signature_value} ->
        {:TBSCertificate, _version, _serial, _signature, _issuer, validity, _subject,
         _subject_public_key_info, _issuer_unique_id, _subject_unique_id, _extensions} =
          tbs_certificate

        case validity do
          {:Validity, not_before, not_after} ->
            # Convert ASN.1 time to DateTime
            case {convert_asn1_time_to_datetime(not_before),
                  convert_asn1_time_to_datetime(not_after)} do
              {{:ok, not_before_dt}, {:ok, not_after_dt}} ->
                {:ok, {not_before_dt, not_after_dt}}

              {{:error, reason}, _} ->
                {:error, "Failed to parse not_before time: #{reason}"}

              {_, {:error, reason}} ->
                {:error, "Failed to parse not_after time: #{reason}"}
            end

          _ ->
            {:error, "Invalid validity format"}
        end

      _ ->
        {:error, "Unsupported certificate format"}
    end
  rescue
    error ->
      {:error, "Failed to extract validity: #{inspect(error)}"}
  end

  defp convert_asn1_time_to_datetime(asn1_time) do
    case asn1_time do
      {:utcTime, time_string} when is_list(time_string) ->
        # Convert charlist to string
        time_str = to_string(time_string)
        parse_utc_time(time_str)

      {:generalTime, time_string} when is_list(time_string) ->
        # Convert charlist to string
        time_str = to_string(time_string)
        parse_general_time(time_str)

      _ ->
        {:error, "Unsupported time format: #{inspect(asn1_time)}"}
    end
  rescue
    error ->
      {:error, "Failed to convert ASN.1 time: #{inspect(error)}"}
  end

  defp parse_utc_time(time_str) do
    # UTCTime format: YYMMDDHHMMSSZ or YYMMDDHHMMSS+HHMM
    case Regex.run(~r/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z?$/, time_str) do
      [_, year_str, month_str, day_str, hour_str, minute_str, second_str] ->
        year = String.to_integer(year_str)
        # Handle Y2K: years 00-49 are 20xx, 50-99 are 19xx
        full_year = if year >= 50, do: 1900 + year, else: 2000 + year

        month = String.to_integer(month_str)
        day = String.to_integer(day_str)
        hour = String.to_integer(hour_str)
        minute = String.to_integer(minute_str)
        second = String.to_integer(second_str)

        case DateTime.new(
               Date.new!(full_year, month, day),
               Time.new!(hour, minute, second),
               "Etc/UTC"
             ) do
          {:ok, datetime} -> {:ok, datetime}
          {:error, reason} -> {:error, "Invalid UTC time: #{reason}"}
        end

      nil ->
        {:error, "Invalid UTC time format: #{time_str}"}
    end
  end

  defp parse_general_time(time_str) do
    # GeneralizedTime format: YYYYMMDDHHMMSSZ or YYYYMMDDHHMMSS+HHMM
    case Regex.run(~r/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z?$/, time_str) do
      [_, year_str, month_str, day_str, hour_str, minute_str, second_str] ->
        year = String.to_integer(year_str)
        month = String.to_integer(month_str)
        day = String.to_integer(day_str)
        hour = String.to_integer(hour_str)
        minute = String.to_integer(minute_str)
        second = String.to_integer(second_str)

        case DateTime.new(Date.new!(year, month, day), Time.new!(hour, minute, second), "Etc/UTC") do
          {:ok, datetime} -> {:ok, datetime}
          {:error, reason} -> {:error, "Invalid general time: #{reason}"}
        end

      nil ->
        {:error, "Invalid general time format: #{time_str}"}
    end
  end

  defp derive_public_key_from_private(private_key) do
    case private_key do
      {:RSAPrivateKey, _version, modulus, public_exponent, _private_exponent, _p, _q, _exponent1,
       _exponent2, _coefficient, _other_prime_infos} ->
        public_key = {:RSAPublicKey, modulus, public_exponent}
        {:ok, public_key}

      _ ->
        {:error, "Unsupported private key format"}
    end
  rescue
    error ->
      {:error, "Failed to derive public key: #{inspect(error)}"}
  end

  defp public_keys_match?(key1, key2) do
    # Convert both keys to comparable format and compare
    normalize_public_key(key1) == normalize_public_key(key2)
  end

  defp normalize_public_key({:RSAPublicKey, modulus, exponent}) do
    {modulus, exponent}
  end

  defp normalize_public_key(other) do
    other
  end

  defp validate_certificate_format(changeset) do
    case get_field(changeset, :certificate) do
      nil ->
        changeset

      cert ->
        if String.contains?(cert, "BEGIN CERTIFICATE") and
             String.contains?(cert, "END CERTIFICATE") do
          # Validate that it's actually a parseable X.509 certificate
          case parse_and_validate_certificate(cert) do
            :ok ->
              changeset

            {:error, reason} ->
              add_error(changeset, :certificate, "invalid X.509 certificate: #{reason}")
          end
        else
          add_error(changeset, :certificate, "must be in PEM format")
        end
    end
  end

  defp validate_private_key_format(changeset) do
    case get_field(changeset, :private_key) do
      nil ->
        changeset

      key ->
        cond do
          # Check if it's a PEM-formatted key
          String.contains?(key, "BEGIN") and String.contains?(key, "PRIVATE KEY") ->
            # Validate that it's actually a parseable private key
            case parse_and_validate_private_key(key) do
              :ok ->
                # If both certificate and private key are present, validate they match
                validate_key_pair_match(changeset)

              {:error, reason} ->
                add_error(changeset, :private_key, "invalid private key: #{reason}")
            end

          # Check if it's an encrypted key (base64 encoded, no PEM headers)
          encrypted_private_key?(key) ->
            # Encrypted keys are valid - skip PEM validation and key pair matching
            changeset

          # Neither PEM nor encrypted format
          true ->
            add_error(changeset, :private_key, "must be in PEM format or encrypted")
        end
    end
  end

  # Check if a string looks like an encrypted private key (base64 encoded)
  defp encrypted_private_key?(key) do
    # Encrypted keys are base64 strings without PEM headers
    # They should be valid base64 and have a reasonable length
    case Base.decode64(key) do
      {:ok, decoded} when byte_size(decoded) >= 48 ->
        # Valid base64 with minimum size (16 salt + 16 IV + 16 tag = 48 bytes minimum)
        true

      _ ->
        false
    end
  end

  defp parse_and_validate_certificate(cert_pem) do
    case :public_key.pem_decode(cert_pem) do
      [pem_entry | _] ->
        # Try to decode the certificate to ensure it's valid
        _certificate = :public_key.pem_entry_decode(pem_entry)
        :ok

      [] ->
        {:error, "no valid PEM entries found"}
    end
  rescue
    error ->
      {:error, "PEM decode failed: #{inspect(error)}"}
  end

  defp parse_and_validate_private_key(key_pem) do
    case :public_key.pem_decode(key_pem) do
      [pem_entry | _] ->
        # Try to decode the private key to ensure it's valid
        _private_key = :public_key.pem_entry_decode(pem_entry)
        :ok

      [] ->
        {:error, "no valid PEM entries found"}
    end
  rescue
    error ->
      {:error, "PEM decode failed: #{inspect(error)}"}
  end

  defp validate_key_pair_match(changeset) do
    cert = get_field(changeset, :certificate)
    key = get_field(changeset, :private_key)

    # Only validate if both are present and not placeholders
    if cert && key &&
         not String.contains?(cert, "PLACEHOLDER") &&
         not String.contains?(key, "PLACEHOLDER") do
      case validate_key_pair(key, cert) do
        {:ok, true} ->
          changeset

        {:error, reason} ->
          add_error(changeset, :private_key, "key pair validation failed: #{reason}")
      end
    else
      changeset
    end
  end

  defp auto_extract_expiration_date(changeset) do
    # Only extract if certificate is present and expires_at is not already set
    case {get_field(changeset, :certificate), get_field(changeset, :expires_at)} do
      {certificate_pem, nil} when is_binary(certificate_pem) ->
        case extract_expiration_date(certificate_pem) do
          {:ok, expires_at} ->
            put_change(changeset, :expires_at, expires_at)

          {:error, reason} ->
            add_error(changeset, :certificate, "Unable to extract expiration date: #{reason}")
        end

      {_, _} ->
        # Certificate not present or expires_at already set
        changeset
    end
  end
end
