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
    field :application_name, :string, virtual: true

    belongs_to :group, Group

    timestamps(type: :utc_datetime)
  end

  @doc """
  Returns a human-readable name for the group application, falling back to a
  type- and ID-qualified label when the application can no longer be resolved.
  """
  def display_name(%__MODULE__{application_name: name}) when is_binary(name), do: name

  def display_name(%__MODULE__{application_type: type, application_id: id}) do
    "Unknown #{type} application (#{id})"
  end

  @doc false
  def changeset(group_application, attrs) do
    group_application
    |> cast(attrs, [:application_id, :application_type, :group_id])
    |> validate_required([:application_id, :application_type, :group_id])
    |> validate_inclusion(:application_type, ["oauth2", "saml"])
    |> unique_constraint([:application_id, :application_type, :group_id],
      name: :group_apps_app_type_group_unique,
      message: "Application is already in this group"
    )
    |> foreign_key_constraint(:group_id)
  end
end
