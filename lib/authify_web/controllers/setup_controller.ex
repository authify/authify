defmodule AuthifyWeb.SetupController do
  use AuthifyWeb, :controller

  import Phoenix.Component

  alias Authify.Accounts
  alias Authify.Configurations
  alias Authify.Organizations

  @doc """
  Shows the initial setup form for creating the first global admin user.
  This should only be accessible when no users exist in the system.
  """
  def new(conn, _params) do
    # Security check: only allow if no users exist
    if Accounts.count_users() > 0 do
      conn
      |> put_flash(:error, "System has already been set up.")
      |> redirect(to: ~p"/login")
    else
      # Create a changeset for the form
      changeset = Accounts.change_user_registration(%Accounts.User{})

      render(conn, :new,
        changeset: changeset,
        form: to_form(changeset),
        tenant_base_domain: "",
        authify_domain: ""
      )
    end
  end

  @doc """
  Creates the first global admin user and sets up the global organization.
  """
  def create(conn, params) do
    user_params = Map.get(params, "user")
    tenant_base_domain = Map.get(params, "tenant_base_domain")
    authify_domain = Map.get(params, "authify_domain", "")

    # Security check: only allow if no users exist
    if Accounts.count_users() > 0 do
      conn
      |> put_flash(:error, "System has already been set up.")
      |> redirect(to: ~p"/login")
    else
      with {:ok, _} <- validate_and_set_tenant_base_domain(tenant_base_domain),
           {:ok, _user} <- Accounts.create_super_admin(user_params),
           :ok <- setup_authify_domain(authify_domain) do
        conn
        |> put_flash(
          :info,
          "Global admin account created successfully! You can now log in."
        )
        |> redirect(to: ~p"/login?org_slug=authify-global")
      else
        {:error, :tenant_base_domain, reason} ->
          changeset = Accounts.change_user_registration(%Accounts.User{}, user_params || %{})

          conn
          |> put_flash(:error, "Tenant base domain #{reason}")
          |> render(:new,
            changeset: changeset,
            form: to_form(changeset),
            tenant_base_domain: tenant_base_domain || "",
            authify_domain: authify_domain
          )

        {:error, changeset} ->
          render(conn, :new,
            changeset: changeset,
            form: to_form(changeset),
            tenant_base_domain: tenant_base_domain || "",
            authify_domain: authify_domain
          )

        {:error, :authify_domain, reason} ->
          changeset = Accounts.change_user_registration(%Accounts.User{}, user_params || %{})

          conn
          |> put_flash(:error, "Authify domain #{reason}")
          |> render(:new,
            changeset: changeset,
            form: to_form(changeset),
            tenant_base_domain: tenant_base_domain || "",
            authify_domain: authify_domain
          )
      end
    end
  end

  defp validate_and_set_tenant_base_domain(nil),
    do: {:error, :tenant_base_domain, "is required"}

  defp validate_and_set_tenant_base_domain(tenant_base_domain) do
    case Configurations.set_global_setting(:tenant_base_domain, tenant_base_domain) do
      {:ok, _} -> {:ok, :set}
      {:error, reason} -> {:error, :tenant_base_domain, reason}
    end
  end

  defp setup_authify_domain(""), do: :ok
  defp setup_authify_domain(nil), do: :ok

  defp setup_authify_domain(authify_domain) do
    global_org = Accounts.get_global_organization()

    # Create CNAME for authify-global organization
    case Organizations.create_cname(%{
           organization_id: global_org.id,
           domain: authify_domain
         }) do
      {:ok, _cname} ->
        # Set email_link_domain to this custom domain (global setting)
        case Configurations.set_global_setting(:email_link_domain, authify_domain) do
          {:ok, _} -> :ok
          {:error, reason} -> {:error, :authify_domain, reason}
        end

      {:error, changeset} ->
        errors = Ecto.Changeset.traverse_errors(changeset, fn {msg, _opts} -> msg end)
        reason = errors |> Map.get(:domain, ["is invalid"]) |> List.first()
        {:error, :authify_domain, reason}
    end
  end
end
