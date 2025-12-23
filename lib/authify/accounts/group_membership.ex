defmodule Authify.Accounts.GroupMembership do
  @moduledoc """
  Join table schema for the many-to-many relationship between Users and Groups.
  Allows users to be members of groups for identity attributes and access control.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias Authify.Accounts.{Group, User}

  schema "group_memberships" do
    belongs_to :user, User
    belongs_to :group, Group

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(group_membership, attrs) do
    group_membership
    |> cast(attrs, [:user_id, :group_id])
    |> validate_required([:user_id, :group_id])
    |> unique_constraint([:user_id, :group_id],
      message: "User is already in this group"
    )
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:group_id)
  end
end
