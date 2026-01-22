defmodule AuthifyWeb.GroupController do
  use AuthifyWeb, :controller

  alias Authify.Accounts
  alias Authify.Accounts.Group
  alias Authify.OAuth
  alias Authify.SAML

  # Safely convert string to atom, only for known valid values
  defp safe_to_atom(string)
       when string in ~w(name description is_active inserted_at updated_at asc desc) do
    String.to_existing_atom(string)
  end

  defp safe_to_atom(string) when is_binary(string), do: :name
  defp safe_to_atom(value), do: value

  def index(conn, params) do
    organization = conn.assigns.current_organization

    # Parse filtering and sorting params
    sort = params["sort"] || "name"
    order = params["order"] || "asc"
    search = params["search"]

    filter_opts = [
      sort: safe_to_atom(sort),
      order: safe_to_atom(order),
      search: search
    ]

    groups = Accounts.list_groups_filtered(organization, filter_opts)

    render(conn, :index,
      groups: groups,
      organization: organization,
      sort: sort,
      order: order,
      search: search
    )
  end

  def show(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    group = get_group_with_details!(id, organization)

    render(conn, :show, group: group, organization: organization)
  end

  def new(conn, _params) do
    organization = conn.assigns.current_organization
    changeset = Accounts.change_group(%Group{}, %{})
    render(conn, :new, changeset: changeset, organization: organization)
  end

  def create(conn, %{"group" => group_params}) do
    organization = conn.assigns.current_organization

    group_params = Map.put(group_params, "organization_id", organization.id)

    case Accounts.create_group(group_params) do
      {:ok, group} ->
        conn
        |> put_flash(:info, "Group created successfully.")
        |> redirect(to: ~p"/#{organization.slug}/groups/#{group}")

      {:error, %Ecto.Changeset{} = changeset} ->
        render(conn, :new, changeset: changeset, organization: organization)
    end
  end

  def edit(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    group = get_group!(id, organization)
    changeset = Accounts.change_group(group, %{})

    render(conn, :edit,
      group: group,
      changeset: changeset,
      organization: organization
    )
  end

  def update(conn, %{"id" => id, "group" => group_params}) do
    organization = conn.assigns.current_organization
    group = get_group!(id, organization)

    case Accounts.update_group(group, group_params) do
      {:ok, group} ->
        conn
        |> put_flash(:info, "Group updated successfully.")
        |> redirect(to: ~p"/#{organization.slug}/groups/#{group}")

      {:error, %Ecto.Changeset{} = changeset} ->
        render(conn, :edit,
          group: group,
          changeset: changeset,
          organization: organization
        )
    end
  end

  def delete(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    group = get_group!(id, organization)
    {:ok, _group} = Accounts.delete_group(group)

    conn
    |> put_flash(:info, "Group deleted successfully.")
    |> redirect(to: ~p"/#{organization.slug}/groups")
  end

  # Member management actions

  def manage_members(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    group = get_group_with_details!(id, organization)

    users = Accounts.list_users(organization.id) |> Authify.Repo.preload(:emails)
    oauth_apps = OAuth.list_oauth_applications(organization)
    saml_providers = SAML.list_service_providers(organization)

    render(conn, :manage_members,
      group: group,
      organization: organization,
      users: users,
      oauth_apps: oauth_apps,
      saml_providers: saml_providers
    )
  end

  def add_user(conn, %{"id" => id, "user_id" => user_id}) do
    organization = conn.assigns.current_organization
    group = get_group!(id, organization)
    user = Accounts.get_user!(user_id)

    case Accounts.add_user_to_group(user, group) do
      {:ok, _membership} ->
        conn
        |> put_flash(:info, "User added to group successfully.")
        |> redirect(to: ~p"/#{organization.slug}/groups/#{id}/members")

      {:error, changeset} ->
        conn
        |> put_flash(:error, "Failed to add user: #{format_errors(changeset)}")
        |> redirect(to: ~p"/#{organization.slug}/groups/#{id}/members")
    end
  end

  def remove_user(conn, %{"id" => id, "user_id" => user_id}) do
    organization = conn.assigns.current_organization
    group = get_group!(id, organization)
    user = Accounts.get_user!(user_id)

    {count, _} = Accounts.remove_user_from_group(user, group)

    if count > 0 do
      conn
      |> put_flash(:info, "User removed from group successfully.")
      |> redirect(to: ~p"/#{organization.slug}/groups/#{id}/members")
    else
      conn
      |> put_flash(:error, "User was not in the group.")
      |> redirect(to: ~p"/#{organization.slug}/groups/#{id}/members")
    end
  end

  def add_application(conn, %{
        "id" => id,
        "application_id" => app_id,
        "application_type" => app_type
      }) do
    organization = conn.assigns.current_organization
    group = get_group!(id, organization)

    case Accounts.add_application_to_group(group, app_id, app_type) do
      {:ok, _member} ->
        conn
        |> put_flash(:info, "Application added to group successfully.")
        |> redirect(to: ~p"/#{organization.slug}/groups/#{id}/members")

      {:error, changeset} ->
        conn
        |> put_flash(:error, "Failed to add application: #{format_errors(changeset)}")
        |> redirect(to: ~p"/#{organization.slug}/groups/#{id}/members")
    end
  end

  def remove_application(conn, %{"id" => id, "member_id" => member_id}) do
    organization = conn.assigns.current_organization
    group = get_group!(id, organization)

    case Accounts.remove_application_from_group(group, member_id) do
      {count, _} when count > 0 ->
        conn
        |> put_flash(:info, "Application removed from group successfully.")
        |> redirect(to: ~p"/#{organization.slug}/groups/#{id}/members")

      _ ->
        conn
        |> put_flash(:error, "Application was not in the group.")
        |> redirect(to: ~p"/#{organization.slug}/groups/#{id}/members")
    end
  end

  # Private helper functions

  defp get_group!(id, organization) do
    Accounts.get_group!(id, organization)
  end

  defp get_group_with_details!(id, organization) do
    group = get_group!(id, organization)

    Authify.Repo.preload(group,
      users: :emails,
      group_applications: [:group]
    )
  end

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
    |> Enum.map_join("; ", fn {field, errors} -> "#{field}: #{Enum.join(errors, ", ")}" end)
  end
end
