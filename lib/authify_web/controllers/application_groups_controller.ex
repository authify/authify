defmodule AuthifyWeb.ApplicationGroupsController do
  use AuthifyWeb, :controller

  alias Authify.Accounts
  alias Authify.Accounts.ApplicationGroup
  alias Authify.OAuth
  alias Authify.SAML

  def index(conn, params) do
    organization = conn.assigns.current_organization

    # Parse filtering and sorting params
    sort = params["sort"] || "name"
    order = params["order"] || "asc"
    search = params["search"]

    filter_opts = [
      sort: String.to_atom(sort),
      order: String.to_atom(order),
      search: search
    ]

    application_groups = Accounts.list_application_groups_filtered(organization, filter_opts)

    render(conn, :index,
      application_groups: application_groups,
      organization: organization,
      sort: sort,
      order: order,
      search: search
    )
  end

  def show(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    application_group = get_application_group_with_details!(id, organization)

    render(conn, :show, application_group: application_group, organization: organization)
  end

  def new(conn, _params) do
    organization = conn.assigns.current_organization
    changeset = Accounts.change_application_group_form(%ApplicationGroup{}, %{})
    render(conn, :new, changeset: changeset, organization: organization)
  end

  def create(conn, %{"application_group" => application_group_params}) do
    organization = conn.assigns.current_organization

    case Accounts.create_application_group(organization, application_group_params) do
      {:ok, application_group} ->
        conn
        |> put_flash(:info, "Application group created successfully.")
        |> redirect(to: ~p"/#{organization.slug}/application_groups/#{application_group}")

      {:error, %Ecto.Changeset{} = changeset} ->
        render(conn, :new, changeset: changeset, organization: organization)
    end
  end

  def edit(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    application_group = get_application_group!(id, organization)
    changeset = Accounts.change_application_group(application_group, %{})

    render(conn, :edit,
      application_group: application_group,
      changeset: changeset,
      organization: organization
    )
  end

  def update(conn, %{"id" => id, "application_group" => application_group_params}) do
    organization = conn.assigns.current_organization
    application_group = get_application_group!(id, organization)

    case Accounts.update_application_group(application_group, application_group_params) do
      {:ok, application_group} ->
        conn
        |> put_flash(:info, "Application group updated successfully.")
        |> redirect(to: ~p"/#{organization.slug}/application_groups/#{application_group}")

      {:error, %Ecto.Changeset{} = changeset} ->
        render(conn, :edit,
          application_group: application_group,
          changeset: changeset,
          organization: organization
        )
    end
  end

  def delete(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    application_group = get_application_group!(id, organization)
    {:ok, _application_group} = Accounts.delete_application_group(application_group)

    conn
    |> put_flash(:info, "Application group deleted successfully.")
    |> redirect(to: ~p"/#{organization.slug}/application_groups")
  end

  # Member management actions

  def manage_members(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    application_group = get_application_group_with_details!(id, organization)

    users = Accounts.list_users(organization.id)
    oauth_apps = OAuth.list_oauth_applications(organization)
    saml_providers = SAML.list_service_providers(organization)

    render(conn, :manage_members,
      application_group: application_group,
      organization: organization,
      users: users,
      oauth_apps: oauth_apps,
      saml_providers: saml_providers
    )
  end

  def add_user(conn, %{"id" => id, "user_id" => user_id}) do
    organization = conn.assigns.current_organization
    application_group = get_application_group!(id, organization)
    user = Accounts.get_user!(user_id)

    case Accounts.add_user_to_application_group(user, application_group) do
      {:ok, _} ->
        conn
        |> put_flash(:info, "User added to group successfully.")
        |> redirect(to: ~p"/#{organization.slug}/application_groups/#{id}/members")

      {:error, _changeset} ->
        conn
        |> put_flash(:error, "User could not be added to group.")
        |> redirect(to: ~p"/#{organization.slug}/application_groups/#{id}/members")
    end
  end

  def remove_user(conn, %{"id" => id, "user_id" => user_id}) do
    organization = conn.assigns.current_organization
    application_group = get_application_group!(id, organization)
    user = Accounts.get_user!(user_id)

    case Accounts.remove_user_from_application_group(user, application_group) do
      {:ok, _} ->
        conn
        |> put_flash(:info, "User removed from group successfully.")
        |> redirect(to: ~p"/#{organization.slug}/application_groups/#{id}/members")

      {:error, _} ->
        conn
        |> put_flash(:error, "User could not be removed from group.")
        |> redirect(to: ~p"/#{organization.slug}/application_groups/#{id}/members")
    end
  end

  def add_application(conn, %{
        "id" => id,
        "application_id" => app_id,
        "application_type" => app_type
      }) do
    organization = conn.assigns.current_organization
    application_group = get_application_group!(id, organization)

    case Accounts.add_application_to_group(application_group, String.to_integer(app_id), app_type) do
      {:ok, _} ->
        conn
        |> put_flash(:info, "Application added to group successfully.")
        |> redirect(to: ~p"/#{organization.slug}/application_groups/#{id}/members")

      {:error, _changeset} ->
        conn
        |> put_flash(:error, "Application could not be added to group.")
        |> redirect(to: ~p"/#{organization.slug}/application_groups/#{id}/members")
    end
  end

  def remove_application(conn, %{"id" => id, "member_id" => member_id}) do
    organization = conn.assigns.current_organization
    application_group = get_application_group!(id, organization)

    member = Authify.Repo.get!(Authify.Accounts.ApplicationGroupMember, member_id)

    if member.application_group_id == application_group.id do
      case Authify.Repo.delete(member) do
        {:ok, _} ->
          conn
          |> put_flash(:info, "Application removed from group successfully.")
          |> redirect(to: ~p"/#{organization.slug}/application_groups/#{id}/members")

        {:error, _} ->
          conn
          |> put_flash(:error, "Application could not be removed from group.")
          |> redirect(to: ~p"/#{organization.slug}/application_groups/#{id}/members")
      end
    else
      conn
      |> put_flash(:error, "Invalid request.")
      |> redirect(to: ~p"/#{organization.slug}/application_groups/#{id}/members")
    end
  end

  # Private helper functions

  defp get_application_group!(id, organization) do
    application_group = Accounts.get_application_group!(id)

    if application_group.organization_id == organization.id do
      application_group
    else
      raise Ecto.NoResultsError, queryable: ApplicationGroup
    end
  end

  defp get_application_group_with_details!(id, organization) do
    application_group = get_application_group!(id, organization)

    # Preload associations
    application_group
    |> Authify.Repo.preload([
      :application_group_members,
      user_application_groups: :user
    ])
  end
end
