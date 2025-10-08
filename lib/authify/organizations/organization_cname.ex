defmodule Authify.Organizations.OrganizationCname do
  @moduledoc """
  Represents a custom CNAME domain for an organization.

  CNAMEs are globally unique across all organizations and can be used
  as alternative domains for accessing the organization's identity provider.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias Authify.Accounts.Organization

  @derive {Jason.Encoder, except: [:__meta__, :organization]}

  schema "organization_cnames" do
    field :domain, :string
    field :verified, :boolean, default: false

    belongs_to :organization, Organization

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(cname, attrs) do
    cname
    |> cast(attrs, [:organization_id, :domain, :verified])
    |> validate_required([:organization_id, :domain])
    |> normalize_domain()
    |> validate_domain_format()
    |> unique_constraint(:domain,
      message: "This domain is already in use by another organization"
    )
  end

  defp normalize_domain(changeset) do
    case get_change(changeset, :domain) do
      nil -> changeset
      domain -> put_change(changeset, :domain, String.downcase(domain))
    end
  end

  defp validate_domain_format(changeset) do
    changeset
    |> validate_format(
      :domain,
      ~r/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/,
      message: "must be a valid domain name"
    )
    |> validate_length(:domain, max: 253, message: "domain name too long")
  end
end
