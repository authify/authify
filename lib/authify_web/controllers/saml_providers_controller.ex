defmodule AuthifyWeb.SAMLProvidersController do
  use AuthifyWeb, :controller

  alias Authify.SAML
  alias Authify.SAML.ServiceProvider

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

    service_providers = SAML.list_service_providers_filtered(organization, filter_opts)

    render(conn, :index,
      service_providers: service_providers,
      organization: organization,
      sort: sort,
      order: order,
      search: search,
      status_filter: status_filter
    )
  end

  def show(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    service_provider = SAML.get_service_provider!(id, organization)
    render(conn, :show, service_provider: service_provider, organization: organization)
  end

  def new(conn, _params) do
    organization = conn.assigns.current_organization
    changeset = SAML.change_service_provider_form(%ServiceProvider{})
    render(conn, :new, changeset: changeset, organization: organization)
  end

  def create(conn, %{"service_provider" => service_provider_params}) do
    organization = conn.assigns.current_organization

    service_provider_params = Map.put(service_provider_params, "organization_id", organization.id)

    case SAML.create_service_provider(service_provider_params) do
      {:ok, service_provider} ->
        conn
        |> put_flash(:info, "SAML service provider created successfully.")
        |> redirect(
          to: ~p"/#{conn.assigns.current_organization.slug}/saml_providers/#{service_provider}"
        )

      {:error, %Ecto.Changeset{} = changeset} ->
        render(conn, :new, changeset: changeset, organization: organization)
    end
  end

  def edit(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    service_provider = SAML.get_service_provider!(id, organization)
    changeset = SAML.change_service_provider(service_provider)

    render(conn, :edit,
      service_provider: service_provider,
      changeset: changeset,
      organization: organization
    )
  end

  def update(conn, %{"id" => id, "service_provider" => service_provider_params}) do
    organization = conn.assigns.current_organization
    service_provider = SAML.get_service_provider!(id, organization)

    case SAML.update_service_provider(service_provider, service_provider_params) do
      {:ok, service_provider} ->
        conn
        |> put_flash(:info, "SAML service provider updated successfully.")
        |> redirect(
          to: ~p"/#{conn.assigns.current_organization.slug}/saml_providers/#{service_provider}"
        )

      {:error, %Ecto.Changeset{} = changeset} ->
        render(conn, :edit,
          service_provider: service_provider,
          changeset: changeset,
          organization: organization
        )
    end
  end

  def delete(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    service_provider = SAML.get_service_provider!(id, organization)
    {:ok, _service_provider} = SAML.delete_service_provider(service_provider)

    conn
    |> put_flash(:info, "SAML service provider deleted successfully.")
    |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/saml_providers")
  end
end
