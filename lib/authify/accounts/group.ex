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
             :__meta__
           ]}

  schema "groups" do
    field :name, :string
    field :description, :string
    field :is_active, :boolean, default: true

    belongs_to :organization, Organization
    has_many :group_memberships, GroupMembership, on_delete: :delete_all
    has_many :group_applications, GroupApplication, on_delete: :delete_all
    many_to_many :users, Authify.Accounts.User, join_through: GroupMembership

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(group, attrs) do
    group
    |> cast(attrs, [:name, :description, :is_active, :organization_id])
    |> validate_required([:name, :organization_id])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_length(:description, max: 1000)
    |> unique_constraint([:name, :organization_id],
      message: "Group name already exists in this organization"
    )
    |> foreign_key_constraint(:organization_id)
  end
end
