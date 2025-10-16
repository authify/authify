defmodule AuthifyWeb.ApplicationsController do
  use AuthifyWeb, :controller

  alias Authify.AuditLog
  alias Authify.OAuth
  alias Authify.OAuth.Application

  # Safely convert string to atom, only for known valid values
  defp safe_to_atom(string)
       when string in ~w(email first_name last_name role inserted_at updated_at name slug client_id entity_id acs_url description asc desc) do
    String.to_existing_atom(string)
  end

  defp safe_to_atom(string) when is_binary(string), do: :inserted_at
  defp safe_to_atom(value), do: value

  def index(conn, params) do
    organization = conn.assigns.current_organization

    # Parse filtering and sorting params
    sort = params["sort"] || "inserted_at"
    order = params["order"] || "desc"
    search = params["search"]
    status_filter = params["status"]

    filter_opts = [
      sort: safe_to_atom(sort),
      order: safe_to_atom(order),
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
        # Log OAuth application creation
        log_application_event(conn, :oauth_client_created, application, %{
          application_type: application.application_type,
          grant_types: application.grant_types
        })

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
      {:ok, updated_application} ->
        # Log OAuth application update
        log_application_event(conn, :oauth_client_updated, updated_application, %{
          application_type: updated_application.application_type,
          grant_types: updated_application.grant_types
        })

        conn
        |> put_flash(:info, "OAuth application updated successfully.")
        |> redirect(
          to: ~p"/#{conn.assigns.current_organization.slug}/applications/#{updated_application}"
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

    # Log OAuth application deletion
    log_application_event(conn, :oauth_client_deleted, application, %{
      application_type: application.application_type,
      client_id: application.client_id
    })

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

  # Helper for audit logging OAuth applications
  defp log_application_event(conn, event_type, application, metadata) do
    organization = conn.assigns.current_organization
    current_user = conn.assigns.current_user

    AuditLog.log_event_async(event_type, %{
      organization_id: organization.id,
      actor_type: "user",
      actor_id: current_user.id,
      actor_name: "#{current_user.first_name} #{current_user.last_name}",
      resource_type: "oauth_application",
      resource_id: application.id,
      outcome: "success",
      ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
      user_agent: Plug.Conn.get_req_header(conn, "user-agent") |> List.first(),
      metadata:
        Map.merge(metadata, %{
          application_name: application.name,
          application_id: application.id
        })
    })
  end
end
