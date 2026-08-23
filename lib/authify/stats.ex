defmodule Authify.Stats do
  @moduledoc """
  Context for system analytics, counting, and reporting functions.
  """

  import Ecto.Query, warn: false

  alias Authify.Accounts.Organization
  alias Authify.Accounts.User
  alias Authify.FilterSort
  alias Authify.Repo

  @doc """
  Returns the total count of users across all organizations.
  """
  def count_users do
    from(u in User, where: u.active == true)
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Returns the count of users in a specific organization.
  """
  def count_users(organization_id) do
    from(u in User,
      where: u.organization_id == ^organization_id and u.active == true
    )
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Lists organizations with stats.
  """
  def list_organizations_with_stats do
    from(o in Organization,
      left_join: u in User,
      on: u.organization_id == o.id and u.active == true,
      group_by: o.id,
      select: %{
        id: o.id,
        name: o.name,
        slug: o.slug,
        active: o.active,
        user_count: count(u.id),
        inserted_at: o.inserted_at,
        updated_at: o.updated_at
      },
      order_by: [desc: o.inserted_at]
    )
    |> Repo.all()
  end

  @doc """
  Returns a filtered and sorted list of organizations with stats.

  ## Options
    * `:sort` - Field to sort by (atom, e.g., :name, :slug, :inserted_at)
    * `:order` - Sort order (:asc or :desc, defaults to :desc)
    * `:search` - Text search across name and slug fields
    * `:status` - Filter by active status (boolean or "all")

  ## Examples

      iex> list_organizations_with_stats_filtered(sort: :name, order: :asc, search: "acme")
      [%{id: 1, name: "Acme Corp", ...}, ...]
  """
  def list_organizations_with_stats_filtered(opts \\ []) do
    base_query =
      from(o in Organization,
        left_join: u in User,
        on: u.organization_id == o.id and u.active == true,
        group_by: o.id,
        select: %{
          id: o.id,
          name: o.name,
          slug: o.slug,
          active: o.active,
          user_count: count(u.id),
          inserted_at: o.inserted_at,
          updated_at: o.updated_at
        }
      )

    base_query
    |> apply_org_stats_filters(opts)
    |> apply_org_stats_search(opts[:search])
    |> apply_org_stats_sorting(opts[:sort], opts[:order])
    |> Repo.all()
  end

  defp apply_org_stats_filters(query, opts) do
    maybe_filter_org_stats_by_status(query, opts[:status])
  end

  defp maybe_filter_org_stats_by_status(query, status),
    do: FilterSort.apply_status_filter(query, :active, status)

  defp apply_org_stats_search(query, search),
    do: FilterSort.apply_multi_text_filter(query, [:name, :slug], search)

  @org_stats_sort_fields [:name, :slug, :inserted_at, :updated_at]

  defp apply_org_stats_sorting(query, sort, order),
    do:
      FilterSort.apply_sort(query, sort, order, @org_stats_sort_fields,
        default: [desc: :inserted_at]
      )

  @doc """
  Gets system stats.
  """
  def get_system_stats do
    %{
      total_users: count_users(),
      total_organizations: count_organizations(),
      organization_count: count_organizations(),
      active_organization_count: count_organizations(),
      active_users: count_users(),
      active_organizations: count_organizations(),
      super_admin_count: count_global_admins(),
      recent_users: get_recent_users()
    }
  end

  @doc """
  Counts organizations.
  """
  def count_organizations do
    from(o in Organization, where: o.active == true)
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Counts inactive organizations since a given date.
  """
  def count_inactive_organizations_since(cutoff_date) do
    from(o in Organization,
      where: o.active == false and o.updated_at < ^cutoff_date
    )
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Gets recent users (compatibility function).
  """
  def get_recent_users(limit \\ 5) do
    from(u in User,
      where: u.active == true,
      order_by: [desc: u.inserted_at],
      limit: ^limit,
      preload: [:organization]
    )
    |> Repo.all()
  end

  @doc """
  Counts active organizations (compatibility function).
  """
  def count_active_organizations do
    count_organizations()
  end

  @doc """
  Counts global admins.
  """
  def count_global_admins do
    global_org = Authify.Accounts.get_global_organization()

    if global_org do
      count_users(global_org.id)
    else
      0
    end
  end

  @doc """
  Counts users created since a given date.
  """
  def count_users_since(date) do
    from(u in User,
      where: u.active == true and u.inserted_at >= ^date
    )
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Counts users by role in a specific organization.
  """
  def count_users_by_role(organization_id, role) do
    from(u in User,
      where: u.organization_id == ^organization_id and u.role == ^role and u.active == true
    )
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Counts users by role globally.
  """
  def count_users_by_role(role) do
    from(u in User,
      where: u.role == ^role and u.active == true
    )
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Counts organizations created since a given date.
  """
  def count_organizations_since(date) do
    from(o in Organization,
      where: o.active == true and o.inserted_at >= ^date
    )
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Counts users by role globally.
  """
  def count_users_by_role_globally(role) do
    count_users_by_role(role)
  end

  @doc """
  Counts active users.
  """
  def count_active_users do
    count_users()
  end

  @doc """
  Counts inactive users.
  """
  def count_inactive_users do
    from(u in User, where: u.active == false)
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Counts organizations created before a given date.
  """
  def count_organizations_created_before(date) do
    from(o in Organization,
      where: o.active == true and o.inserted_at < ^date
    )
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Counts users created before a given date.
  """
  def count_users_created_before(date) do
    from(u in User,
      where: u.active == true and u.inserted_at < ^date
    )
    |> Repo.aggregate(:count, :id)
  end
end
