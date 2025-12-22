defmodule Authify.Accounts.GroupApplication do
  @moduledoc """
  Join table schema for the many-to-many relationship between Groups and applications
  (OAuth2 or SAML). Allows applications to be members of groups, granting access to
  all users in that group.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias Authify.Accounts.Group

  schema "group_applications" do
    field :application_id, :integer
    field :application_type, :string

    belongs_to :group, Group

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(group_application, attrs) do
    group_application
    |> cast(attrs, [:application_id, :application_type, :group_id])
    |> validate_required([:application_id, :application_type, :group_id])
    |> validate_inclusion(:application_type, ["oauth2", "saml"])
    |> unique_constraint([:application_id, :application_type, :group_id],
      message: "Application is already in this group"
    )
    |> foreign_key_constraint(:group_id)
  end
end
