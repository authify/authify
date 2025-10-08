defmodule Authify.Accounts.Organization do
  @moduledoc """
  Organization schema for single-tenant structure with direct user relationships.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias Authify.Accounts.User
  alias Authify.Configurations.Configuration
  alias Authify.Organizations.OrganizationCname

  @derive {Jason.Encoder, except: [:users, :cnames, :configuration, :__meta__]}

  @type t :: %__MODULE__{
          id: integer(),
          name: String.t(),
          slug: String.t(),
          active: boolean(),
          users: [User.t()],
          inserted_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  schema "organizations" do
    field :name, :string
    field :slug, :string
    field :active, :boolean, default: true

    has_many :users, User, on_delete: :delete_all
    has_many :cnames, OrganizationCname, on_delete: :delete_all

    has_one :configuration, Configuration,
      foreign_key: :configurable_id,
      where: [configurable_type: "Organization"],
      on_delete: :delete_all

    timestamps(type: :utc_datetime)
  end

  @required_fields [:name]
  @optional_fields [:slug, :active]

  @doc false
  def changeset(organization, attrs) do
    organization
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> maybe_generate_slug()
    |> validate_required([:name, :slug])
    |> validate_length(:name, min: 2, max: 255)
    |> validate_format(:slug, ~r/^[a-z0-9-]+$/,
      message: "only lowercase letters, numbers, and hyphens allowed"
    )
    |> validate_length(:slug, min: 2, max: 50)
    |> unique_constraint(:slug)
  end

  defp maybe_generate_slug(%Ecto.Changeset{changes: %{name: name}} = changeset) do
    case get_field(changeset, :slug) do
      nil ->
        slug =
          name
          |> String.downcase()
          |> String.replace(~r/[^a-z0-9]/, "-")
          |> String.replace(~r/-+/, "-")

        put_change(changeset, :slug, slug)

      _slug ->
        changeset
    end
  end

  defp maybe_generate_slug(changeset), do: changeset
end
