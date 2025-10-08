defmodule AuthifyWeb.ApplicationsController do
  use AuthifyWeb, :controller

  alias Authify.OAuth
  alias Authify.OAuth.Application

  def index(conn, params) do
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

    applications = OAuth.list_oauth_applications_filtered(organization, filter_opts)

    render(conn, :index,
      applications: applications,
      organization: organization,
      sort: sort,
      order: order,
      search: search,
      status_filter: status_filter
    )
  end

  def show(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    application = OAuth.get_oauth_application!(id, organization)
    render(conn, :show, application: application, organization: organization)
  end

  def new(conn, _params) do
    organization = conn.assigns.current_organization
    changeset = OAuth.change_application_form(%Application{})
    render(conn, :new, changeset: changeset, organization: organization)
  end

  def create(conn, %{"application" => application_params}) do
    organization = conn.assigns.current_organization

    application_params =
      application_params
      |> Map.put("organization_id", organization.id)
      |> normalize_grant_types()

    case OAuth.create_application(application_params) do
      {:ok, application} ->
        conn
        |> put_flash(:info, "OAuth application created successfully.")
        |> redirect(
          to: ~p"/#{conn.assigns.current_organization.slug}/applications/#{application}"
        )

      {:error, %Ecto.Changeset{} = changeset} ->
        render(conn, :new, changeset: changeset, organization: organization)
    end
  end

  def edit(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    application = OAuth.get_oauth_application!(id, organization)
    changeset = OAuth.change_application(application)

    render(conn, :edit,
      application: application,
      changeset: changeset,
      organization: organization
    )
  end

  def update(conn, %{"id" => id, "application" => application_params}) do
    organization = conn.assigns.current_organization
    application = OAuth.get_oauth_application!(id, organization)

    application_params = normalize_grant_types(application_params)

    case OAuth.update_application(application, application_params) do
      {:ok, application} ->
        conn
        |> put_flash(:info, "OAuth application updated successfully.")
        |> redirect(
          to: ~p"/#{conn.assigns.current_organization.slug}/applications/#{application}"
        )

      {:error, %Ecto.Changeset{} = changeset} ->
        render(conn, :edit,
          application: application,
          changeset: changeset,
          organization: organization
        )
    end
  end

  def delete(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    application = OAuth.get_oauth_application!(id, organization)
    {:ok, _application} = OAuth.delete_application(application)

    conn
    |> put_flash(:info, "OAuth application deleted successfully.")
    |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/applications")
  end

  # Private helper functions

  defp normalize_grant_types(%{"grant_types" => grant_types} = params)
       when is_list(grant_types) do
    # Convert array of grant types to space-separated string
    Map.put(params, "grant_types", Enum.join(grant_types, " "))
  end

  defp normalize_grant_types(params), do: params
end
