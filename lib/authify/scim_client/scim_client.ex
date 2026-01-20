defmodule Authify.SCIMClient.ScimClient do
  @moduledoc """
  Schema for SCIM 2.0 client configurations for outbound provisioning.
  Enables automatic user/group provisioning to downstream applications.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias Authify.Accounts.Organization
  alias Authify.SCIMClient.{ExternalId, SyncLog}

  @derive {Jason.Encoder,
           except: [
             :organization,
             :sync_logs,
             :external_ids,
             :auth_credential,
             :__meta__
           ]}

  schema "scim_clients" do
    field :name, :string
    field :description, :string
    field :base_url, :string
    field :auth_type, :string, default: "bearer"
    field :auth_credential, Authify.Encrypted.Binary
    field :auth_username, :string
    field :attribute_mapping, :string
    field :is_active, :boolean, default: false
    field :sync_users, :boolean, default: true
    field :sync_groups, :boolean, default: true

    belongs_to :organization, Organization
    has_many :sync_logs, SyncLog
    has_many :external_ids, ExternalId

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(scim_client, attrs) do
    scim_client
    |> cast(attrs, [
      :name,
      :description,
      :base_url,
      :auth_type,
      :auth_credential,
      :auth_username,
      :attribute_mapping,
      :is_active,
      :sync_users,
      :sync_groups,
      :organization_id
    ])
    |> validate_required([:name, :base_url, :auth_type, :organization_id])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_inclusion(:auth_type, ["bearer", "basic"])
    |> validate_url(:base_url)
    |> validate_auth_requirements()
    |> validate_attribute_mapping()
    |> unique_constraint(:name, name: :scim_clients_name_org_unique)
  end

  defp validate_url(changeset, field) do
    validate_change(changeset, field, fn _, url ->
      uri = URI.parse(url)

      cond do
        is_nil(uri.scheme) or uri.scheme not in ["http", "https"] ->
          [{field, "must be a valid HTTP or HTTPS URL"}]

        is_nil(uri.host) ->
          [{field, "must include a hostname"}]

        true ->
          []
      end
    end)
  end

  defp validate_auth_requirements(changeset) do
    auth_type = get_field(changeset, :auth_type)
    # Only validate auth_credential if it's being changed or this is a new record
    is_new_record = changeset.data.__meta__.state == :built
    credential_changed = get_change(changeset, :auth_credential) != nil

    case auth_type do
      "bearer" ->
        if is_new_record or credential_changed do
          validate_required(changeset, [:auth_credential])
        else
          changeset
        end

      "basic" ->
        if is_new_record or credential_changed do
          validate_required(changeset, [:auth_username, :auth_credential])
        else
          changeset
        end

      _ ->
        changeset
    end
  end

  defp validate_attribute_mapping(changeset) do
    validate_change(changeset, :attribute_mapping, fn _, mapping ->
      case Jason.decode(mapping) do
        {:ok, decoded} when is_map(decoded) ->
          []

        {:ok, _} ->
          [:attribute_mapping, "must be a JSON object"]

        {:error, _} ->
          [:attribute_mapping, "must be valid JSON"]
      end
    end)
  end
end
