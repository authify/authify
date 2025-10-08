defmodule AuthifyWeb.OrganizationsController do
  use AuthifyWeb, :controller

  alias Authify.Accounts

  # All actions require being in the global organization
  def action(conn, _) do
    if conn.assigns.current_organization.slug != "authify-global" do
      conn
      |> put_flash(:error, "Access denied.")
      |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/dashboard")
      |> halt()
    else
      apply(__MODULE__, action_name(conn), [conn, conn.params])
    end
  end

  def index(conn, params) do
    user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    # Parse filtering and sorting params
    sort = params["sort"] || "inserted_at"
    order = params["order"] || "desc"
    search = params["search"]
    status_filter = params["status"]

    filter_opts = [
      sort: String.to_atom(sort),
      order: String.to_atom(order),
      search: search,
      status: status_filter
    ]

    organizations = Accounts.list_organizations_with_stats_filtered(filter_opts)

    render(conn, :index,
      user: user,
      organization: organization,
      organizations: organizations,
      sort: sort,
      order: order,
      search: search,
      status_filter: status_filter
    )
  end

  def show(conn, %{"id" => id}) do
    user = conn.assigns.current_user
    organization = conn.assigns.current_organization
    target_organization = Accounts.get_organization!(id)

    # Get organization stats
    users = Accounts.list_users(target_organization.id)
    invitations = Accounts.list_invitations(target_organization.id)

    render(conn, :show,
      user: user,
      organization: organization,
      target_organization: target_organization,
      users: users,
      invitations: invitations
    )
  end

  def new(conn, _params) do
    user = conn.assigns.current_user
    organization = conn.assigns.current_organization
    changeset = Accounts.change_organization(%Accounts.Organization{})

    render(conn, :new,
      user: user,
      organization: organization,
      changeset: changeset
    )
  end

  def create(conn, %{"organization" => org_params}) do
    case Accounts.create_organization(org_params) do
      {:ok, organization} ->
        conn
        |> put_flash(:info, "Organization '#{organization.name}' created successfully.")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/organizations")

      {:error, changeset} ->
        user = conn.assigns.current_user
        organization = conn.assigns.current_organization

        render(conn, :new,
          user: user,
          organization: organization,
          changeset: changeset
        )
    end
  end

  def edit(conn, %{"id" => id}) do
    user = conn.assigns.current_user
    organization = conn.assigns.current_organization
    target_organization = Accounts.get_organization!(id)
    changeset = Accounts.change_organization(target_organization)

    render(conn, :edit,
      user: user,
      organization: organization,
      target_organization: target_organization,
      changeset: changeset
    )
  end

  def update(conn, %{"id" => id, "organization" => org_params}) do
    target_organization = Accounts.get_organization!(id)

    case Accounts.update_organization(target_organization, org_params) do
      {:ok, organization} ->
        conn
        |> put_flash(:info, "Organization '#{organization.name}' updated successfully.")
        |> redirect(
          to: ~p"/#{conn.assigns.current_organization.slug}/organizations/#{organization.id}"
        )

      {:error, changeset} ->
        user = conn.assigns.current_user
        organization = conn.assigns.current_organization

        render(conn, :edit,
          user: user,
          organization: organization,
          target_organization: target_organization,
          changeset: changeset
        )
    end
  end

  def delete(conn, %{"id" => id}) do
    target_organization = Accounts.get_organization!(id)

    # Prevent deletion of global organization
    if target_organization.slug == "authify-global" do
      conn
      |> put_flash(:error, "Cannot delete the global organization.")
      |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/organizations")
      |> halt()
    end

    case Accounts.delete_organization(target_organization) do
      {:ok, _organization} ->
        conn
        |> put_flash(:info, "Organization '#{target_organization.name}' deleted successfully.")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/organizations")

      {:error, _changeset} ->
        conn
        |> put_flash(:error, "Could not delete organization. It may have active users.")
        |> redirect(
          to:
            ~p"/#{conn.assigns.current_organization.slug}/organizations/#{target_organization.id}"
        )
    end
  end

  def switch_to_organization(conn, %{"id" => id}) do
    target_organization = Accounts.get_organization!(id)

    # Update the user's session to point to the specified organization
    conn
    |> put_session(:current_organization_id, target_organization.id)
    |> put_flash(:info, "Switched to #{target_organization.name}.")
    |> redirect(to: ~p"/#{target_organization.slug}/dashboard")
  end

  def disable(conn, %{"id" => id}) do
    target_organization = Accounts.get_organization!(id)

    # Prevent disabling global organization
    if target_organization.slug == "authify-global" do
      conn
      |> put_flash(:error, "Cannot disable the global organization.")
      |> redirect(
        to: ~p"/#{conn.assigns.current_organization.slug}/organizations/#{target_organization.id}"
      )
      |> halt()
    end

    case Accounts.update_organization(target_organization, %{"active" => false}) do
      {:ok, organization} ->
        conn
        |> put_flash(:info, "Organization '#{organization.name}' disabled.")
        |> redirect(
          to: ~p"/#{conn.assigns.current_organization.slug}/organizations/#{organization.id}"
        )

      {:error, _changeset} ->
        conn
        |> put_flash(:error, "Could not disable organization.")
        |> redirect(
          to:
            ~p"/#{conn.assigns.current_organization.slug}/organizations/#{target_organization.id}"
        )
    end
  end

  def enable(conn, %{"id" => id}) do
    target_organization = Accounts.get_organization!(id)

    case Accounts.update_organization(target_organization, %{"active" => true}) do
      {:ok, organization} ->
        conn
        |> put_flash(:info, "Organization '#{organization.name}' enabled.")
        |> redirect(
          to: ~p"/#{conn.assigns.current_organization.slug}/organizations/#{organization.id}"
        )

      {:error, _changeset} ->
        conn
        |> put_flash(:error, "Could not enable organization.")
        |> redirect(
          to:
            ~p"/#{conn.assigns.current_organization.slug}/organizations/#{target_organization.id}"
        )
    end
  end
end
