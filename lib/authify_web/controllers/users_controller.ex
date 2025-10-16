defmodule AuthifyWeb.UsersController do
  use AuthifyWeb, :controller

  alias Authify.Accounts
  alias Authify.AuditLog

  # Safely convert string to atom, only for known valid values
  defp safe_to_atom(string)
       when string in ~w(email first_name last_name role inserted_at updated_at name slug client_id entity_id acs_url description asc desc) do
    String.to_existing_atom(string)
  end

  defp safe_to_atom(string) when is_binary(string), do: :email
  defp safe_to_atom(value), do: value

  def index(conn, params) do
    user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    # Parse filtering and sorting params
    sort = params["sort"] || "email"
    order = params["order"] || "asc"
    search = params["search"]
    role_filter = params["role"]
    status_filter = params["status"]

    filter_opts = [
      sort: safe_to_atom(sort),
      order: safe_to_atom(order),
      search: search,
      role: role_filter,
      status: status_filter
    ]

    if organization.slug == "authify-global" do
      # Global organization - show all global admins
      users = Accounts.list_global_admins()

      render(conn, :index,
        user: user,
        organization: organization,
        users: users,
        user_count: length(users),
        is_global_view: true,
        sort: sort,
        order: order,
        search: search,
        role_filter: role_filter,
        status_filter: status_filter
      )
    else
      # Regular organization - show organization users with filtering
      users = Accounts.list_users_filtered(organization.id, filter_opts)

      render(conn, :index,
        user: user,
        organization: organization,
        users: users,
        user_count: length(users),
        is_global_view: false,
        sort: sort,
        order: order,
        search: search,
        role_filter: role_filter,
        status_filter: status_filter
      )
    end
  end

  def show(conn, %{"id" => id}) do
    user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    if organization.slug == "authify-global" do
      # Global organization - can view any user
      target_user = Accounts.get_user_globally!(id)
      # For global view, get invitations sent BY this user
      invitations = Accounts.list_invitations_by_inviter(target_user.id)

      render_user_show(conn, target_user, invitations, user, organization, true)
    else
      # Regular organization - can only view users in same organization
      target_user = Accounts.get_user!(id)
      # Verify user belongs to the current organization
      if Accounts.User.member_of?(target_user, organization.id) do
        # Get invitations sent BY this user
        invitations = Accounts.list_invitations_by_inviter(target_user.id)
        render_user_show(conn, target_user, invitations, user, organization, false)
      else
        conn
        |> put_status(:not_found)
        |> put_view(AuthifyWeb.ErrorHTML)
        |> render(:"404")
        |> halt()
      end
    end
  end

  defp render_user_show(conn, target_user, invitations, user, organization, is_global_view) do
    render(conn, :show,
      user: user,
      organization: organization,
      target_user: target_user,
      invitations: invitations,
      is_global_view: is_global_view
    )
  end

  # Global admin actions (only available when viewing global organization)
  def promote_to_global_admin(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization

    if organization.slug != "authify-global" do
      conn
      |> put_flash(:error, "Access denied.")
      |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/users")
      |> halt()
    end

    target_user = Accounts.get_user_globally!(id)

    # Promote user to admin role
    case Accounts.update_user_role(target_user, "admin") do
      :ok ->
        conn
        |> put_flash(
          :info,
          "#{Accounts.User.full_name(target_user)} promoted to global admin successfully."
        )
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/users/#{target_user.id}")

      {:error, _changeset} ->
        conn
        |> put_flash(:error, "Could not promote user to global admin.")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/users/#{target_user.id}")
    end
  end

  def demote_from_global_admin(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization

    if organization.slug != "authify-global" do
      conn
      |> put_flash(:error, "Access denied.")
      |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/users")
      |> halt()
    end

    target_user = Accounts.get_user_globally!(id)

    # Cannot demote yourself
    if target_user.id == conn.assigns.current_user.id do
      conn
      |> put_flash(:error, "You cannot demote yourself.")
      |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/users/#{target_user.id}")
      |> halt()
    end

    # For now, we'll remove them from the global organization
    # In a real implementation, you might want to move them to a different organization
    case Accounts.remove_user_from_organization(target_user.id, organization.id) do
      :ok ->
        conn
        |> put_flash(:info, "#{Accounts.User.full_name(target_user)} removed from global admin.")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/users")

      {:error, _reason} ->
        conn
        |> put_flash(:error, "Could not demote global admin.")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/users/#{target_user.id}")
    end
  end

  def update_role(conn, %{"id" => id, "role" => new_role}) do
    organization = conn.assigns.current_organization

    target_user =
      if organization.slug == "authify-global" do
        Accounts.get_user_globally!(id)
      else
        user = Accounts.get_user!(id)
        # Verify user belongs to current organization
        if Accounts.User.member_of?(user, organization.id) do
          user
        else
          conn
          |> put_status(:not_found)
          |> put_view(AuthifyWeb.ErrorHTML)
          |> render(:"404")
          |> halt()
        end
      end

    # Prevent users from demoting themselves from admin to user
    if target_user.id == conn.assigns.current_user.id do
      if target_user.organization_id == organization.id && target_user.role == "admin" &&
           new_role == "user" do
        conn
        |> put_flash(:error, "You cannot demote yourself from admin privileges.")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/users/#{target_user.id}")
        |> halt()
      end
    end

    case Accounts.update_user_role(target_user, new_role) do
      {:ok, updated_user} ->
        # Log role change
        log_audit_event(conn, :role_assigned, updated_user, %{
          target_user_email: target_user.email,
          old_role: target_user.role,
          new_role: new_role
        })

        conn
        |> put_flash(
          :info,
          "#{Accounts.User.full_name(updated_user)}'s role updated to #{new_role}."
        )
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/users/#{updated_user.id}")

      {:error, _changeset} ->
        conn
        |> put_flash(:error, "Could not update user role.")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/users/#{target_user.id}")
    end
  end

  def force_password_reset(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization

    target_user =
      if organization.slug == "authify-global" do
        Accounts.get_user_globally!(id)
      else
        user = Accounts.get_user!(id)
        # Verify user belongs to current organization
        if Accounts.User.member_of?(user, organization.id) do
          user
        else
          conn
          |> put_status(:not_found)
          |> put_view(AuthifyWeb.ErrorHTML)
          |> render(:"404")
          |> halt()
        end
      end

    case Accounts.force_password_reset(target_user) do
      {:ok, _user} ->
        conn
        |> put_flash(
          :info,
          "Password reset initiated for #{Accounts.User.full_name(target_user)}."
        )
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/users/#{target_user.id}")

      {:error, _changeset} ->
        conn
        |> put_flash(:error, "Could not reset user password.")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/users/#{target_user.id}")
    end
  end

  def disable_user(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization

    target_user =
      if organization.slug == "authify-global" do
        Accounts.get_user_globally!(id)
      else
        user = Accounts.get_user_with_organizations!(id)
        # Verify user belongs to current organization
        if Accounts.User.member_of?(user, organization.id) do
          user
        else
          conn
          |> put_status(:not_found)
          |> put_view(AuthifyWeb.ErrorHTML)
          |> render(:"404")
          |> halt()

          # This return value won't be reached due to halt()
          nil
        end
      end

    # Prevent users from disabling themselves
    if target_user.id == conn.assigns.current_user.id do
      conn
      |> put_flash(:error, "You cannot disable your own account.")
      |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/users/#{target_user.id}")
      |> halt()
    end

    case Accounts.disable_user(target_user) do
      {:ok, disabled_user} ->
        # Log user disable
        log_audit_event(conn, :user_disabled, disabled_user, %{
          target_user_email: target_user.email
        })

        conn
        |> put_flash(:info, "#{Accounts.User.full_name(target_user)} has been disabled.")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/users/#{target_user.id}")

      {:error, _changeset} ->
        conn
        |> put_flash(:error, "Could not disable user.")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/users/#{target_user.id}")
    end
  end

  def enable_user(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization

    if organization.slug == "authify-global" do
      target_user = Accounts.get_user_globally!(id)

      case Accounts.enable_user(target_user) do
        {:ok, enabled_user} ->
          # Log user enable
          log_audit_event(conn, :user_enabled, enabled_user, %{
            target_user_email: target_user.email
          })

          conn
          |> put_flash(:info, "#{Accounts.User.full_name(target_user)} has been enabled.")
          |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/users/#{target_user.id}")

        {:error, _changeset} ->
          conn
          |> put_flash(:error, "Could not enable user.")
          |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/users/#{target_user.id}")
      end
    else
      user = Accounts.get_user_with_organizations!(id)
      # For enable action, check organization membership without active status
      if user.organization_id == organization.id do
        case Accounts.enable_user(user) do
          {:ok, enabled_user} ->
            # Log user enable
            log_audit_event(conn, :user_enabled, enabled_user, %{
              target_user_email: user.email
            })

            conn
            |> put_flash(:info, "#{Accounts.User.full_name(user)} has been enabled.")
            |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/users/#{user.id}")

          {:error, _changeset} ->
            conn
            |> put_flash(:error, "Could not enable user.")
            |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/users/#{user.id}")
        end
      else
        conn
        |> put_status(:not_found)
        |> put_view(AuthifyWeb.ErrorHTML)
        |> render(:"404")
      end
    end
  end

  def new(conn, _params) do
    organization = conn.assigns.current_organization
    current_user = conn.assigns.current_user

    # Check if user is admin
    if Accounts.User.admin?(current_user, organization.id) ||
         Accounts.User.super_admin?(current_user) do
      # Allow user creation in any organization, including global
      changeset = Accounts.change_user_form(%Accounts.User{})

      render(conn, :new,
        changeset: changeset,
        organization: organization
      )
    else
      conn
      |> put_flash(:error, "You must be an administrator to create users.")
      |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/users")
      |> halt()
    end
  end

  # Private helper for audit logging to reduce repetition
  defp log_audit_event(conn, event_type, target_user, metadata) do
    organization = conn.assigns.current_organization
    current_user = conn.assigns.current_user

    AuditLog.log_event_async(event_type, %{
      organization_id: organization.id,
      actor_type: "user",
      actor_id: current_user.id,
      actor_name: "#{current_user.first_name} #{current_user.last_name}",
      resource_type: "user",
      resource_id: target_user && target_user.id,
      outcome: "success",
      ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
      user_agent: Plug.Conn.get_req_header(conn, "user-agent") |> List.first(),
      metadata: metadata
    })
  end

  def create(conn, %{"user" => user_params}) do
    organization = conn.assigns.current_organization
    current_user = conn.assigns.current_user

    # Check if user is admin
    if Accounts.User.admin?(current_user, organization.id) ||
         Accounts.User.super_admin?(current_user) do
      # Allow user creation in any organization, including global
      # Extract role from params, default to "user"
      role = Map.get(user_params, "role", "user")
      user_attrs = Map.delete(user_params, "role")

      case Accounts.create_user_with_role(user_attrs, organization.id, role) do
        {:ok, user} ->
          # Log user creation
          log_audit_event(conn, :user_created, user, %{
            created_user_email: user.email,
            created_user_role: role
          })

          conn
          |> put_flash(:info, "#{Accounts.User.full_name(user)} has been created successfully.")
          |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/users/#{user.id}")

        {:error, changeset} ->
          render(conn, :new,
            changeset: changeset,
            organization: organization
          )
      end
    else
      conn
      |> put_flash(:error, "You must be an administrator to create users.")
      |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/users")
      |> halt()
    end
  end
end
