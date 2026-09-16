defmodule Authify.Groups do
  @moduledoc """
  Context for managing groups, group membership, and group applications.
  """

  import Ecto.Query, warn: false

  alias Authify.Accounts.{
    Group,
    GroupApplication,
    GroupMembership,
    Organization,
    User
  }

  alias Authify.FilterSort
  alias Authify.Repo

  @doc """
  Returns the list of groups for an organization.
  """
  def list_groups(%Organization{id: org_id}) do
    Group
    |> where([g], g.organization_id == ^org_id)
    |> order_by([g], asc: g.name)
    |> Repo.all()
  end

  @doc """
  Returns a filtered and sorted list of groups for an organization.

  ## Options
    * `:sort` - Field to sort by (atom, e.g., :name, :inserted_at)
    * `:order` - Sort order (:asc or :desc, defaults to :asc)
    * `:search` - Text search across name and description fields
    * `:status` - Filter by is_active status (boolean or "all")

  ## Examples

      iex> list_groups_filtered(org, sort: :name, order: :desc, search: "admin")
      [%Group{}, ...]
  """
  def list_groups_filtered(%Organization{id: org_id}, opts \\ []) do
    query =
      from(g in Group,
        where: g.organization_id == ^org_id
      )

    query
    |> apply_group_filters(opts)
    |> apply_group_search(opts[:search])
    |> apply_group_sorting(opts[:sort], opts[:order])
    |> Repo.all()
  end

  defp apply_group_filters(query, opts) do
    maybe_filter_group_by_status(query, opts[:status])
  end

  defp maybe_filter_group_by_status(query, status),
    do: FilterSort.apply_status_filter(query, :is_active, status, default_all: true)

  defp apply_group_search(query, search),
    do: FilterSort.apply_multi_text_filter(query, [:name, :description], search)

  @group_sort_fields [:name, :description, :is_active, :inserted_at, :updated_at]

  defp apply_group_sorting(query, sort, order),
    do: FilterSort.apply_sort(query, sort, order, @group_sort_fields, default: [asc: :name])

  @doc """
  Gets a single group by ID within an organization.
  """
  def get_group!(id, %Organization{id: org_id}) do
    Group
    |> where([g], g.id == ^id and g.organization_id == ^org_id)
    |> Repo.one!()
  end

  @doc """
  Gets a single group by ID (without organization scoping).
  Returns nil if the group does not exist.
  """
  def get_group(id) when is_binary(id) do
    case Integer.parse(id) do
      {int_id, ""} -> get_group(int_id)
      _ -> nil
    end
  end

  def get_group(id) when is_integer(id) do
    from(g in Group,
      where: g.id == ^id,
      preload: [:users]
    )
    |> Repo.one()
  end

  @doc """
  Creates a group.
  """
  def create_group(attrs \\ %{}) do
    %Group{}
    |> Group.changeset(attrs)
    |> Group.apply_scim_timestamps(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a group.
  """
  def update_group(%Group{} = group, attrs) do
    group
    |> Group.changeset(attrs)
    |> Group.apply_scim_timestamps(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a group.
  """
  def delete_group(%Group{} = group) do
    result = Repo.delete(group)

    case result do
      {:ok, deleted_group} ->
        Authify.SCIM.Provisioning.broadcast_resource_event(deleted_group, :deleted, :group)
        {:ok, deleted_group}

      error ->
        error
    end
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking group changes.
  """
  def change_group(%Group{} = group, attrs \\ %{}) do
    Group.changeset(group, attrs)
  end

  @doc """
  Adds a user to a group.

  Returns a validation error if the user does not belong to the group's
  organization, or if the user is already a member of the group.
  """
  def add_user_to_group(%User{} = user, %Group{} = group) do
    %GroupMembership{}
    |> GroupMembership.changeset(%{user_id: user.id, group_id: group.id})
    |> validate_user_in_organization(user, group)
    |> Repo.insert()
  end

  defp validate_user_in_organization(
         %Ecto.Changeset{valid?: false} = changeset,
         _user,
         _group
       ),
       do: changeset

  defp validate_user_in_organization(
         changeset,
         %User{organization_id: org_id},
         %Group{organization_id: org_id}
       )
       when not is_nil(org_id),
       do: changeset

  defp validate_user_in_organization(changeset, _user, _group) do
    Ecto.Changeset.add_error(changeset, :user_id, "does not belong to this organization")
  end

  @doc """
  Returns the users available to add to a group, excluding those already in it.
  """
  def available_group_users(%Group{} = group, %Organization{} = organization) do
    group = Repo.preload(group, :users)
    member_ids = MapSet.new(group.users, & &1.id)

    organization.id
    |> Authify.Accounts.list_users()
    |> Repo.preload(:emails)
    |> Enum.reject(&MapSet.member?(member_ids, &1.id))
  end

  @doc """
  Removes a user from a group.
  """
  def remove_user_from_group(%User{id: user_id}, %Group{id: group_id}) do
    from(gm in GroupMembership,
      where: gm.user_id == ^user_id and gm.group_id == ^group_id
    )
    |> Repo.delete_all()
  end

  @doc """
  Lists all users in a group.
  """
  def list_group_members(%Group{} = group) do
    group
    |> Repo.preload(:users)
    |> Map.get(:users)
  end

  @doc """
  Lists all groups for a user.
  """
  def list_user_groups(%User{} = user) do
    user
    |> Repo.preload(:groups)
    |> Map.get(:groups)
  end

  @doc """
  Removes an application from a group by member ID.
  """
  def remove_application_from_group(%Group{id: group_id}, member_id) do
    from(ga in GroupApplication,
      where: ga.id == ^member_id and ga.group_id == ^group_id
    )
    |> Repo.delete_all()
  end

  @doc """
  Adds an application to a group.

  Application IDs may be provided as integers or numeric strings; they are
  normalized by the changeset. Invalid or blank IDs, or IDs that do not belong
  to the group's organization, result in a validation error rather than raising.
  """
  def add_application_to_group(%Group{} = group, application_id, application_type) do
    %GroupApplication{}
    |> GroupApplication.changeset(%{
      group_id: group.id,
      application_id: application_id,
      application_type: application_type
    })
    |> validate_application_in_organization(group)
    |> Repo.insert()
  end

  defp validate_application_in_organization(%Ecto.Changeset{valid?: false} = changeset, _group) do
    changeset
  end

  defp validate_application_in_organization(changeset, %Group{organization_id: org_id}) do
    type = Ecto.Changeset.get_field(changeset, :application_type)
    id = Ecto.Changeset.get_field(changeset, :application_id)

    if application_in_organization?(type, id, org_id) do
      changeset
    else
      Ecto.Changeset.add_error(
        changeset,
        :application_id,
        "does not exist in this organization"
      )
    end
  end

  defp application_in_organization?("oauth2", id, org_id) do
    Authify.OAuth.Application
    |> where([a], a.id == ^id and a.organization_id == ^org_id)
    |> Repo.exists?()
  end

  defp application_in_organization?("saml", id, org_id) do
    Authify.SAML.ServiceProvider
    |> where([sp], sp.id == ^id and sp.organization_id == ^org_id)
    |> Repo.exists?()
  end

  defp application_in_organization?(_type, _id, _org_id), do: false

  @doc """
  Returns the applications available to add to a group, excluding those already
  assigned to it.

  Returns a map with `:oauth_apps` and `:saml_providers` keys.
  """
  def available_group_applications(%Group{} = group, %Organization{} = organization) do
    group = Repo.preload(group, :group_applications)

    assigned =
      group.group_applications
      |> MapSet.new(&{&1.application_type, &1.application_id})

    oauth_apps =
      Authify.OAuth.list_oauth_applications(organization)
      |> Enum.reject(&MapSet.member?(assigned, {"oauth2", &1.id}))

    saml_providers =
      Authify.SAML.list_service_providers(organization)
      |> Enum.reject(&MapSet.member?(assigned, {"saml", &1.id}))

    %{oauth_apps: oauth_apps, saml_providers: saml_providers}
  end

  @doc """
  Populates the `:application_name` virtual field on each group application so
  templates can display human-readable names instead of raw IDs.

  Lookups are scoped to the given organization.
  """
  def annotate_application_names(%Group{} = group, %Organization{} = organization) do
    group = Repo.preload(group, :group_applications)
    group_applications = group.group_applications

    oauth_ids =
      for ga <- group_applications, ga.application_type == "oauth2", do: ga.application_id

    saml_ids = for ga <- group_applications, ga.application_type == "saml", do: ga.application_id

    oauth_names = names_by_id(Authify.OAuth.Application, oauth_ids, organization)
    saml_names = names_by_id(Authify.SAML.ServiceProvider, saml_ids, organization)

    annotated =
      Enum.map(group_applications, fn ga ->
        names =
          case ga.application_type do
            "oauth2" -> oauth_names
            "saml" -> saml_names
            _ -> %{}
          end

        %{ga | application_name: Map.get(names, ga.application_id)}
      end)

    %{group | group_applications: annotated}
  end

  defp names_by_id(_schema, [], _organization), do: %{}

  defp names_by_id(schema, ids, %Organization{id: org_id}) do
    from(a in schema,
      where: a.id in ^ids and a.organization_id == ^org_id,
      select: {a.id, a.name}
    )
    |> Repo.all()
    |> Map.new()
  end

  @doc """
  Gets user accessible applications through their groups.
  """
  def get_user_accessible_applications(%User{} = user, %Organization{} = organization) do
    # Get all active groups that the user belongs to
    user_group_ids =
      from(gm in GroupMembership,
        join: g in Group,
        on: g.id == gm.group_id,
        where: gm.user_id == ^user.id and g.is_active == true,
        select: gm.group_id
      )
      |> Repo.all()

    if Enum.empty?(user_group_ids) do
      %{
        oauth2_applications: [],
        saml_service_providers: []
      }
    else
      # Get all application members for those groups
      application_members =
        from(ga in GroupApplication,
          where: ga.group_id in ^user_group_ids,
          select: {ga.application_id, ga.application_type}
        )
        |> Repo.all()

      # Separate OAuth and SAML application IDs
      {oauth_ids, saml_ids} =
        Enum.reduce(application_members, {[], []}, fn
          {app_id, "oauth2"}, {oauth_acc, saml_acc} -> {[app_id | oauth_acc], saml_acc}
          {app_id, "saml"}, {oauth_acc, saml_acc} -> {oauth_acc, [app_id | saml_acc]}
          _, acc -> acc
        end)

      # Fetch OAuth applications
      oauth2_applications =
        if Enum.empty?(oauth_ids) do
          []
        else
          alias Authify.OAuth.Application

          from(app in Application,
            where:
              app.id in ^oauth_ids and app.organization_id == ^organization.id and
                app.is_active == true
          )
          |> Repo.all()
        end

      # Fetch SAML service providers
      saml_service_providers =
        if Enum.empty?(saml_ids) do
          []
        else
          alias Authify.SAML.ServiceProvider

          from(sp in ServiceProvider,
            where:
              sp.id in ^saml_ids and sp.organization_id == ^organization.id and
                sp.is_active == true
          )
          |> Repo.all()
        end

      %{
        oauth2_applications: oauth2_applications,
        saml_service_providers: saml_service_providers
      }
    end
  end
end
