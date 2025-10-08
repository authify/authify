defmodule AuthifyWeb.OrganizationController do
  use AuthifyWeb, :controller

  alias Authify.Accounts
  alias Authify.Accounts.{Organization, User}
  alias Authify.Configurations

  def new(conn, _params) do
    # Check if organization registration is allowed
    unless Configurations.get_global_setting(:allow_organization_registration) do
      conn
      |> put_flash(
        :error,
        "Organization registration is currently disabled. Please contact an administrator."
      )
      |> redirect(to: ~p"/login")
    else
      # Create empty changesets without validation for initial form display
      organization_changeset = %Organization{} |> Ecto.Changeset.change()
      user_changeset = %User{} |> Ecto.Changeset.change()

      render(conn, :new,
        organization_changeset: organization_changeset,
        user_changeset: user_changeset,
        page_title: "Create Organization"
      )
    end
  end

  def create(conn, %{"signup" => signup_params}) do
    # Check if organization registration is allowed
    unless Configurations.get_global_setting(:allow_organization_registration) do
      conn
      |> put_flash(
        :error,
        "Organization registration is currently disabled. Please contact an administrator."
      )
      |> redirect(to: ~p"/login")
    else
      do_create(conn, signup_params)
    end
  end

  defp do_create(conn, signup_params) do
    org_params = signup_params["organization"] || %{}
    user_params = signup_params["user"] || %{}

    case Accounts.create_organization_with_admin(org_params, user_params) do
      {:ok, {organization, _user}} ->
        conn
        |> put_flash(:info, "Organization created successfully! Welcome to Authify.")
        |> redirect(to: ~p"/organizations/#{organization.id}/success")

      {:error, %Ecto.Changeset{} = changeset} ->
        # Determine if the error is from organization or user
        {org_changeset, user_changeset} =
          case changeset.data do
            %Organization{} ->
              {changeset, Accounts.change_user_registration(%User{}, user_params)}

            %User{} ->
              {Accounts.change_organization(%Organization{}, org_params), changeset}
          end

        conn
        |> put_flash(
          :error,
          "There was an error creating your organization. Please check the form below."
        )
        |> render(:new,
          organization_changeset: org_changeset,
          user_changeset: user_changeset,
          page_title: "Create Organization"
        )
    end
  end

  def success(conn, %{"id" => id}) do
    organization = Accounts.get_organization!(id)

    render(conn, :success,
      organization: organization,
      page_title: "Welcome to #{organization.name}"
    )
  end
end
