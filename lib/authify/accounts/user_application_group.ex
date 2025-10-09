defmodule Authify.Accounts.UserApplicationGroup do
  use Ecto.Schema
  import Ecto.Changeset

  alias Authify.Accounts.{ApplicationGroup, User}

  schema "user_application_groups" do
    belongs_to :user, User
    belongs_to :application_group, ApplicationGroup

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(user_application_group, attrs) do
    user_application_group
    |> cast(attrs, [:user_id, :application_group_id])
    |> validate_required([:user_id, :application_group_id])
    |> unique_constraint([:user_id, :application_group_id],
      message: "User is already in this application group"
    )
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:application_group_id)
  end
end
