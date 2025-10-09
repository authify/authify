defmodule Authify.Accounts.ApplicationGroup do
  use Ecto.Schema
  import Ecto.Changeset

  alias Authify.Accounts.{ApplicationGroupMember, Organization, UserApplicationGroup}

  @derive {Jason.Encoder,
           except: [
             :organization,
             :user_application_groups,
             :application_group_members,
             :__meta__
           ]}

  schema "application_groups" do
    field :name, :string
    field :description, :string
    field :is_active, :boolean, default: true

    belongs_to :organization, Organization
    has_many :user_application_groups, UserApplicationGroup, on_delete: :delete_all
    has_many :application_group_members, ApplicationGroupMember, on_delete: :delete_all
    many_to_many :users, Authify.Accounts.User, join_through: UserApplicationGroup

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(application_group, attrs) do
    application_group
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
