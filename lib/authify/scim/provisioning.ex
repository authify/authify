defmodule Authify.SCIM.Provisioning do
  @moduledoc """
  SCIM provisioning operations for users and groups.

  Handles all SCIM user/group CRUD (list, count, retrieve by external_id,
  create, update) plus broadcast of resource events through Phoenix.PubSub.

  `broadcast_resource_event/3` is public so callers in `Authify.Accounts`
  (the `delete_user`/`delete_group` paths) can invoke it too.
  """

  import Ecto.Query, warn: false

  alias Authify.Accounts.{Group, User}
  alias Authify.Repo
  alias Authify.SCIM.{AttributeMapper, FilterParser, QueryFilter}

  ## External ID lookups

  @doc """
  Gets a user by external_id within an organization.

  Returns nil if user not found or external_id doesn't match organization.
  """
  def get_user_by_external_id(external_id, organization_id)
      when is_binary(external_id) and is_integer(organization_id) do
    Repo.get_by(User, external_id: external_id, organization_id: organization_id)
    |> Repo.preload(:organization)
  end

  def get_user_by_external_id(_external_id, _organization_id), do: nil

  @doc """
  Gets a group by external_id within an organization.

  Returns nil if group not found or external_id doesn't match organization.
  """
  def get_group_by_external_id(external_id, organization_id)
      when is_binary(external_id) and is_integer(organization_id) do
    Repo.get_by(Group, external_id: external_id, organization_id: organization_id)
  end

  def get_group_by_external_id(_external_id, _organization_id), do: nil

  ## SCIM list with filter and pagination

  @doc """
  Lists users for SCIM with optional filter and pagination.

  ## Options
    * `:page` - Page number (default: 1)
    * `:per_page` - Results per page (default: 25, max: 100)
    * `:filter` - SCIM filter query string
    * `:sort_by` - SCIM attribute to sort by (e.g., "userName", "meta.created")
    * `:sort_order` - Sort direction, "ascending" or "descending" (default: "ascending")

  Returns `{:ok, users}` on success or `{:error, reason}` if filter is invalid.
  """
  def list_users_scim(organization_id, opts \\ []) do
    page = Keyword.get(opts, :page, 1)
    per_page = min(Keyword.get(opts, :per_page, 25), 100)
    offset = (page - 1) * per_page

    base_query =
      from(u in User,
        where: u.organization_id == ^organization_id,
        preload: [:organization, :groups]
      )

    query_result =
      case Keyword.get(opts, :filter) do
        nil ->
          {:ok, base_query}

        filter_string ->
          with {:ok, ast} <- FilterParser.parse(filter_string),
               {:ok, filtered_query} <- QueryFilter.apply_filter(base_query, ast, :user) do
            {:ok, filtered_query}
          else
            {:error, reason} -> {:error, reason}
          end
      end

    case query_result do
      {:ok, query} ->
        query = apply_scim_sort(query, opts[:sort_by], opts[:sort_order])

        users =
          query
          |> limit(^per_page)
          |> offset(^offset)
          |> Repo.all()

        {:ok, users}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Lists groups for SCIM with optional filter and pagination.

  ## Options
    * `:page` - Page number (default: 1)
    * `:per_page` - Results per page (default: 25, max: 100)
    * `:filter` - SCIM filter query string
    * `:sort_by` - SCIM attribute to sort by (e.g., "displayName")
    * `:sort_order` - Sort direction, "ascending" or "descending" (default: "ascending")

  Returns `{:ok, groups}` on success or `{:error, reason}` if filter is invalid.
  """
  def list_groups_scim(organization_id, opts \\ []) do
    page = Keyword.get(opts, :page, 1)
    per_page = min(Keyword.get(opts, :per_page, 25), 100)
    offset = (page - 1) * per_page

    base_query =
      from(g in Group,
        where: g.organization_id == ^organization_id,
        preload: [:users]
      )

    query_result =
      case Keyword.get(opts, :filter) do
        nil ->
          {:ok, base_query}

        filter_string ->
          with {:ok, ast} <- FilterParser.parse(filter_string),
               {:ok, filtered_query} <- QueryFilter.apply_filter(base_query, ast, :group) do
            {:ok, filtered_query}
          else
            {:error, reason} -> {:error, reason}
          end
      end

    case query_result do
      {:ok, query} ->
        query = apply_scim_sort(query, opts[:sort_by], opts[:sort_order])

        groups =
          query
          |> limit(^per_page)
          |> offset(^offset)
          |> Repo.all()

        {:ok, groups}

      {:error, reason} ->
        {:error, reason}
    end
  end

  ## SCIM counts

  @doc """
  Counts users for SCIM pagination (includes inactive users).

  ## Options
    * `:filter` - SCIM filter query string

  Returns `{:ok, count}` on success or `{:error, reason}` if filter is invalid.
  """
  def count_users_scim(organization_id, opts \\ []) do
    base_query =
      from(u in User,
        where: u.organization_id == ^organization_id
      )

    query_result =
      case Keyword.get(opts, :filter) do
        nil ->
          {:ok, base_query}

        filter_string ->
          with {:ok, ast} <- FilterParser.parse(filter_string),
               {:ok, filtered_query} <- QueryFilter.apply_filter(base_query, ast, :user) do
            {:ok, filtered_query}
          else
            {:error, reason} -> {:error, reason}
          end
      end

    case query_result do
      {:ok, query} ->
        count = Repo.aggregate(query, :count, :id)
        {:ok, count}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Counts groups for SCIM pagination.

  ## Options
    * `:filter` - SCIM filter query string

  Returns `{:ok, count}` on success or `{:error, reason}` if filter is invalid.
  """
  def count_groups_scim(organization_id, opts \\ []) do
    base_query =
      from(g in Group,
        where: g.organization_id == ^organization_id
      )

    query_result =
      case Keyword.get(opts, :filter) do
        nil ->
          {:ok, base_query}

        filter_string ->
          with {:ok, ast} <- FilterParser.parse(filter_string),
               {:ok, filtered_query} <- QueryFilter.apply_filter(base_query, ast, :group) do
            {:ok, filtered_query}
          else
            {:error, reason} -> {:error, reason}
          end
      end

    case query_result do
      {:ok, query} ->
        count = Repo.aggregate(query, :count, :id)
        {:ok, count}

      {:error, reason} ->
        {:error, reason}
    end
  end

  ## SCIM create / update operations

  @doc """
  Creates a user via SCIM provisioning.

  Sets scim_created_at and scim_updated_at timestamps.
  Generates a random password if not provided.
  """
  def create_user_scim(attrs, organization_id) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    password = generate_random_password()

    attrs =
      attrs
      |> Map.put(:organization_id, organization_id)
      |> Map.put(:scim_created_at, now)
      |> Map.put(:scim_updated_at, now)
      |> Map.put(:password, password)
      |> Map.put(:password_confirmation, password)

    result =
      %User{}
      |> User.registration_changeset(attrs)
      |> User.apply_scim_timestamps(attrs)
      |> Repo.insert()

    case result do
      {:ok, user} ->
        broadcast_resource_event(user, :created, :user)
        {:ok, user}

      error ->
        error
    end
  end

  @doc """
  Updates a user via SCIM provisioning.

  Updates scim_updated_at timestamp.
  """
  def update_user_scim(%User{} = user, attrs) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    attrs = Map.put(attrs, :scim_updated_at, now)

    result =
      user
      |> User.changeset(attrs)
      |> User.apply_scim_timestamps(attrs)
      |> Repo.update()

    case result do
      {:ok, updated_user} ->
        # Preload emails for SCIM provisioning
        user_with_emails = Repo.preload(updated_user, :emails, force: true)
        broadcast_resource_event(user_with_emails, :updated, :user)
        {:ok, updated_user}

      error ->
        error
    end
  end

  @doc """
  Creates a group via SCIM provisioning.
  """
  def create_group_scim(attrs, organization_id) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    attrs =
      attrs
      |> Map.put(:organization_id, organization_id)
      |> Map.put(:scim_created_at, now)
      |> Map.put(:scim_updated_at, now)

    result =
      %Group{}
      |> Group.changeset(attrs)
      |> Group.apply_scim_timestamps(attrs)
      |> Repo.insert()

    case result do
      {:ok, group} ->
        broadcast_resource_event(group, :created, :group)
        {:ok, group}

      error ->
        error
    end
  end

  @doc """
  Updates a group via SCIM provisioning.
  """
  def update_group_scim(%Group{} = group, attrs) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    attrs = Map.put(attrs, :scim_updated_at, now)

    result =
      group
      |> Group.changeset(attrs)
      |> Group.apply_scim_timestamps(attrs)
      |> Repo.update()

    case result do
      {:ok, updated_group} ->
        broadcast_resource_event(updated_group, :updated, :group)
        {:ok, updated_group}

      error ->
        error
    end
  end

  @doc """
  Applies SCIM PATCH operations to a group.

  This is a placeholder for Phase 6 implementation.
  SCIM PATCH operations for groups (especially members array management)
  will be implemented when the SCIM Groups controller is built.
  """
  def patch_group_scim(%Group{} = _group, _patch_ops) do
    {:error, :not_implemented}
  end

  ## Private helpers

  defp apply_scim_sort(query, nil, _sort_order), do: query

  defp apply_scim_sort(query, sort_by, sort_order) when is_binary(sort_by) do
    # Determine resource type from query
    resource_type =
      case query.from do
        %{source: {"users", _}} -> :user
        %{source: {"groups", _}} -> :group
        _ -> nil
      end

    if resource_type do
      case AttributeMapper.scim_to_ecto_field(sort_by, resource_type) do
        {:ok, field_atom} ->
          direction =
            case sort_order do
              "descending" -> :desc
              _ -> :asc
            end

          from(r in query, order_by: [{^direction, field(r, ^field_atom)}])

        {:error, _} ->
          query
      end
    else
      query
    end
  end

  defp generate_random_password do
    upper = Enum.take_random(?A..?Z, 6) |> List.to_string()
    lower = Enum.take_random(?a..?z, 6) |> List.to_string()
    digits = Enum.take_random(?0..?9, 6) |> List.to_string()
    special = Enum.take_random(~c"!@#$%^&*", 6) |> List.to_string()

    (upper <> lower <> digits <> special)
    |> String.graphemes()
    |> Enum.shuffle()
    |> Enum.join()
  end

  @doc """
  Broadcasts a SCIM resource lifecycle event via Phoenix.PubSub.

  Called by both `Authify.SCIM.Provisioning.*_scim/2` creation/update paths
  and directly by `Authify.Accounts.delete_user`/`delete_group`.
  """
  def broadcast_resource_event(resource, event, resource_type)
      when event in [:created, :updated, :deleted] and
             resource_type in [:user, :group] do
    org_id = resource.organization_id

    Phoenix.PubSub.broadcast(
      Authify.PubSub,
      "scim_provisioning:org_#{org_id}",
      {event, resource_type, resource}
    )

    :ok
  rescue
    _ -> :ok
  end
end
