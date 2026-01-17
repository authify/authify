defmodule Authify.Accounts.Group do
  @moduledoc """
  Schema for groups, which serve multiple purposes:
  - Identity attributes sent in SAML assertions and OIDC claims
  - Application access control (users in a group can access certain applications)
  - General organization and categorization of users

  Replaces the legacy ApplicationGroup concept with a unified group system.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias Authify.Accounts.{GroupApplication, GroupMembership, Organization}

  @derive {Jason.Encoder,
           except: [
             :organization,
             :group_memberships,
             :group_applications,
             :scim_created_at,
             :scim_updated_at,
             :__meta__
           ]}

  schema "groups" do
    field :name, :string
    field :description, :string
    field :is_active, :boolean, default: true

    # SCIM provisioning fields
    field :external_id, :string
    field :scim_created_at, :utc_datetime
    field :scim_updated_at, :utc_datetime

    belongs_to :organization, Organization
    has_many :group_memberships, GroupMembership, on_delete: :delete_all
    has_many :group_applications, GroupApplication, on_delete: :delete_all
    many_to_many :users, Authify.Accounts.User, join_through: GroupMembership

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(group, attrs) do
    group
    |> cast(attrs, [:name, :description, :is_active, :organization_id, :external_id])
    |> validate_required([:name, :organization_id])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_length(:description, max: 1000)
    |> validate_external_id()
    |> unique_constraint([:name, :organization_id],
      message: "Group name already exists in this organization"
    )
    |> foreign_key_constraint(:organization_id)
  end

  defp validate_external_id(changeset) do
    changeset
    |> validate_length(:external_id, max: 255)
    |> validate_format(:external_id, ~r/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/,
      message:
        "must start with alphanumeric character and can contain letters, numbers, dots, hyphens, and underscores"
    )
    |> validate_external_id_immutability()
    |> unique_constraint([:external_id, :organization_id],
      message: "external_id already exists in this organization"
    )
  end

  def apply_scim_timestamps(changeset, attrs \\ %{}) do
    changeset
    |> allow_scim_field(:scim_created_at, Map.get(attrs, :scim_created_at))
    |> allow_scim_field(:scim_updated_at, Map.get(attrs, :scim_updated_at))
  end

  defp allow_scim_field(changeset, _field, nil), do: changeset

  defp allow_scim_field(changeset, field, value) do
    Ecto.Changeset.put_change(changeset, field, value)
  end

  # Ensure external_id cannot be changed once set
  defp validate_external_id_immutability(changeset) do
    case {get_field(changeset, :id), get_change(changeset, :external_id)} do
      {id, new_external_id} when not is_nil(id) and not is_nil(new_external_id) ->
        # This is an update (group has an id)
        old_external_id = changeset.data.external_id

        if old_external_id && old_external_id != new_external_id do
          add_error(changeset, :external_id, "cannot be changed once set")
        else
          changeset
        end

      _ ->
        # This is a new group or external_id is not being changed
        changeset
    end
  end
end
