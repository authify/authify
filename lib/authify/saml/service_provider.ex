defmodule Authify.SAML.ServiceProvider do
  @moduledoc """
  Schema for SAML service provider configurations. Manages SP metadata including
  entity ID, ACS URL, and SLS URL. Supports configurable attribute mapping and
  signature/encryption settings.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @derive {Jason.Encoder, except: [:saml_sessions, :organization, :__meta__]}

  schema "service_providers" do
    field :name, :string
    field :entity_id, :string
    field :acs_url, :string
    field :sls_url, :string
    field :certificate, :string
    field :metadata, :string
    field :attribute_mapping, :string
    field :sign_requests, :boolean, default: false
    field :sign_assertions, :boolean, default: true
    field :encrypt_assertions, :boolean, default: false
    field :is_active, :boolean, default: false

    belongs_to :organization, Authify.Accounts.Organization
    has_many :saml_sessions, Authify.SAML.Session

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(service_provider, attrs) do
    service_provider
    |> cast(attrs, [
      :name,
      :entity_id,
      :acs_url,
      :sls_url,
      :certificate,
      :metadata,
      :attribute_mapping,
      :sign_requests,
      :sign_assertions,
      :encrypt_assertions,
      :is_active,
      :organization_id
    ])
    |> validate_required([:name, :entity_id, :acs_url, :organization_id])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_format(:entity_id, ~r/^https?:\/\//, message: "must be a valid URL")
    |> validate_format(:acs_url, ~r/^https?:\/\//, message: "must be a valid URL")
    |> validate_format(:sls_url, ~r/^https?:\/\//,
      message: "must be a valid URL",
      allow_blank: true
    )
    |> validate_certificate()
    |> validate_attribute_mapping()
    |> unique_constraint(:entity_id)
    |> foreign_key_constraint(:organization_id)
  end

  @doc false
  def form_changeset(service_provider, attrs \\ %{}) do
    service_provider
    |> cast(attrs, [
      :name,
      :entity_id,
      :acs_url,
      :sls_url,
      :certificate,
      :metadata,
      :attribute_mapping,
      :sign_requests,
      :sign_assertions,
      :encrypt_assertions,
      :is_active,
      :organization_id
    ])
  end

  defp validate_certificate(changeset) do
    case get_field(changeset, :certificate) do
      nil ->
        changeset

      cert_string ->
        # Basic validation that it looks like a PEM certificate
        if String.contains?(cert_string, "-----BEGIN CERTIFICATE-----") and
             String.contains?(cert_string, "-----END CERTIFICATE-----") do
          changeset
        else
          add_error(changeset, :certificate, "must be a valid PEM certificate")
        end
    end
  end

  defp validate_attribute_mapping(changeset) do
    case get_field(changeset, :attribute_mapping) do
      nil ->
        changeset

      "" ->
        changeset

      mapping_string ->
        case Jason.decode(mapping_string) do
          {:ok, _mapping} -> changeset
          {:error, _} -> add_error(changeset, :attribute_mapping, "must be valid JSON")
        end
    end
  end

  def default_attribute_mapping do
    %{
      "email" => "email",
      "first_name" => "first_name",
      "last_name" => "last_name",
      "name" => "{{first_name}} {{last_name}}"
    }
    |> Jason.encode!()
  end

  def decode_attribute_mapping(%__MODULE__{attribute_mapping: nil}), do: get_default_mapping()
  def decode_attribute_mapping(%__MODULE__{attribute_mapping: ""}), do: get_default_mapping()

  def decode_attribute_mapping(%__MODULE__{attribute_mapping: mapping}) when is_binary(mapping) do
    case Jason.decode(mapping) do
      {:ok, decoded} -> decoded
      {:error, _} -> get_default_mapping()
    end
  end

  def decode_attribute_mapping(_), do: get_default_mapping()

  defp get_default_mapping do
    %{
      "email" => "email",
      "first_name" => "first_name",
      "last_name" => "last_name",
      "name" => "{{first_name}} {{last_name}}"
    }
  end
end
