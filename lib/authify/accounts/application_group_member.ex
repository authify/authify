defmodule Authify.Accounts.ApplicationGroupMember do
  use Ecto.Schema
  import Ecto.Changeset

  alias Authify.Accounts.ApplicationGroup

  schema "application_group_members" do
    field :application_id, :integer
    field :application_type, :string

    belongs_to :application_group, ApplicationGroup

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(application_group_member, attrs) do
    application_group_member
    |> cast(attrs, [:application_id, :application_type, :application_group_id])
    |> validate_required([:application_id, :application_type, :application_group_id])
    |> validate_inclusion(:application_type, ["oauth2", "saml"])
    |> unique_constraint([:application_id, :application_type, :application_group_id],
      message: "Application is already in this group"
    )
    |> foreign_key_constraint(:application_group_id)
  end
end
