defmodule AuthifyWeb.Plugs.OrganizationPlug do
  @moduledoc """
  Plug to load the organization from the :org_slug path parameter.

  This plug extracts the organization slug from the URL path and loads
  the corresponding organization from the database. The organization is
  then stored in conn.assigns.current_organization for use by controllers
  and views.

  If the organization is not found, returns a 404 error.
  """
  import Plug.Conn
  import Phoenix.Controller

  alias Authify.Accounts

  def init(opts), do: opts

  def call(conn, _opts) do
    case conn.path_params do
      %{"org_slug" => slug} when is_binary(slug) ->
        case Accounts.get_organization_by_slug(slug) do
          nil ->
            conn
            |> put_status(:not_found)
            |> put_view(AuthifyWeb.ErrorHTML)
            |> render(:"404")
            |> halt()

          organization ->
            assign(conn, :current_organization, organization)
        end

      _ ->
        conn
        |> put_status(:bad_request)
        |> put_view(AuthifyWeb.ErrorHTML)
        |> render(:"400")
        |> halt()
    end
  end
end
