defmodule Authify.Accounts.Scope do
  @moduledoc """
  Represents a scope (permission) assigned to a scopeable resource.

  This is a polymorphic association that can be used with:
  - PersonalAccessToken
  - OAuth Application
  - Any other resource that needs scopes
  """
  use Ecto.Schema
  import Ecto.Changeset

  schema "scopes" do
    field :scope, :string
    field :scopeable_type, :string
    field :scopeable_id, :id

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(scope, attrs) do
    scope
    |> cast(attrs, [:scope, :scopeable_type, :scopeable_id])
    |> validate_required([:scope, :scopeable_type, :scopeable_id])
    |> validate_scope()
    |> unique_constraint([:scope, :scopeable_type, :scopeable_id],
      name: :scopes_scope_scopeable_type_scopeable_id_index
    )
  end

  defp validate_scope(changeset) do
    case get_field(changeset, :scope) do
      nil ->
        changeset

      scope_value ->
        if scope_value in Authify.Scopes.all_valid_scopes() do
          changeset
        else
          add_error(changeset, :scope, "is not a valid scope")
        end
    end
  end
end
