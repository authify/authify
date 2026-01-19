defmodule Authify.SCIMClient.ExternalId do
  @moduledoc """
  Schema for tracking external IDs from SCIM providers. Maps Authify resources
  (users, groups) to their external IDs in downstream systems.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias Authify.SCIMClient.ScimClient

  @derive {Jason.Encoder,
           except: [
             :scim_client,
             :__meta__
           ]}

  schema "scim_external_ids" do
    field :resource_type, :string
    field :resource_id, :integer
    field :external_id, :string

    belongs_to :scim_client, ScimClient

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(external_id, attrs) do
    external_id
    |> cast(attrs, [:scim_client_id, :resource_type, :resource_id, :external_id])
    |> validate_required([:scim_client_id, :resource_type, :resource_id, :external_id])
    |> validate_inclusion(:resource_type, ["User", "Group"])
    |> unique_constraint([:scim_client_id, :resource_type, :resource_id],
      name: :scim_external_ids_unique
    )
  end
end
