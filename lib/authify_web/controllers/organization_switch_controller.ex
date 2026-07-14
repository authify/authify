defmodule AuthifyWeb.OrganizationSwitchController do
  use AuthifyWeb, :controller

  alias Authify.Accounts

  def switch_to_global(conn, _params) do
    global_org = Accounts.get_global_organization!()

    # Update the user's session to point to the global organization
    conn
    |> put_session(:current_organization_id, global_org.id)
    |> put_flash(:info, "Switched to global administration.")
    |> redirect(to: ~p"/#{global_org.slug}/dashboard")
  end

  def switch_to_organization(conn, %{"slug" => slug}) do
    current_org = conn.assigns.current_organization

    case Accounts.get_organization_by_slug(slug) do
      nil ->
        conn
        |> put_flash(:error, "Organization not found.")
        |> redirect(to: ~p"/#{current_org.slug}/dashboard")

      organization ->
        # Update the user's session to point to the specified organization
        conn
        |> put_session(:current_organization_id, organization.id)
        |> put_flash(:info, "Switched to #{organization.name}.")
        |> redirect(to: ~p"/#{organization.slug}/dashboard")
    end
  end
end
