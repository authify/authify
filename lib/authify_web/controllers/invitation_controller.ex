defmodule AuthifyWeb.InvitationController do
  use AuthifyWeb, :controller

  alias Authify.Accounts
  alias Authify.Accounts.{Invitation, User}
  alias Authify.AuditLog

  def index(conn, _params) do
    user = conn.assigns.current_user
    organization = conn.assigns.current_organization
    invitations = Accounts.list_invitations(organization.id)

    render(conn, :index,
      user: user,
      organization: organization,
      invitations: invitations,
      page_title: "Invitations"
    )
  end

  def new(conn, _params) do
    user = conn.assigns.current_user
    organization = conn.assigns.current_organization
    changeset = Accounts.change_invitation(%Invitation{})

    render(conn, :new,
      user: user,
      organization: organization,
      changeset: changeset,
      page_title: "Invite User"
    )
  end

  def create(conn, %{"invitation" => invitation_params}) do
    organization = conn.assigns.current_organization
    current_user = conn.assigns.current_user

    invitation_params_with_org = Map.put(invitation_params, "organization_id", organization.id)

    case Accounts.create_invitation_and_send_email(invitation_params_with_org, current_user) do
      {:ok, invitation} ->
        # Log invitation creation
        AuditLog.log_event_async(:user_invited, %{
          organization_id: organization.id,
          user_id: current_user.id,
          actor_type: "user",
          actor_name: "#{current_user.first_name} #{current_user.last_name}",
          outcome: "success",
          ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
          user_agent: Plug.Conn.get_req_header(conn, "user-agent") |> List.first(),
          metadata: %{
            invitation_id: invitation.id,
            invited_email: invitation.email,
            invited_role: invitation.role
          }
        })

        conn
        |> put_flash(:info, "Invitation sent successfully!")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/invitations")

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_flash(:error, "There was an error sending the invitation.")
        |> render(:new,
          user: current_user,
          organization: organization,
          changeset: changeset,
          page_title: "Invite User"
        )
    end
  end

  def show(conn, %{"id" => id}) do
    user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    invitation =
      Accounts.get_invitation!(id) |> Authify.Repo.preload([:invited_by, :organization])

    # Ensure invitation belongs to current organization
    if invitation.organization_id == organization.id do
      render(conn, :show,
        user: user,
        organization: organization,
        invitation: invitation,
        page_title: "Invitation Details"
      )
    else
      conn
      |> put_flash(:error, "Invitation not found.")
      |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/invitations")
    end
  end

  def delete(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    current_user = conn.assigns.current_user
    invitation = Accounts.get_invitation!(id)

    # Ensure invitation belongs to current organization
    if invitation.organization_id == organization.id do
      {:ok, _invitation} = Accounts.delete_invitation(invitation)

      # Log invitation revocation
      AuditLog.log_event_async(:invitation_revoked, %{
        organization_id: organization.id,
        user_id: current_user.id,
        actor_type: "user",
        actor_name: "#{current_user.first_name} #{current_user.last_name}",
        outcome: "success",
        ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
        user_agent: Plug.Conn.get_req_header(conn, "user-agent") |> List.first(),
        metadata: %{
          invitation_id: invitation.id,
          invited_email: invitation.email
        }
      })

      conn
      |> put_flash(:info, "Invitation cancelled successfully.")
      |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/invitations")
    else
      conn
      |> put_flash(:error, "Invitation not found.")
      |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/invitations")
    end
  end

  def accept(conn, %{"token" => token}) do
    case Accounts.get_invitation_by_token(token) do
      nil ->
        conn
        |> put_flash(:error, "Invalid or expired invitation.")
        |> redirect(to: ~p"/")

      invitation ->
        if Invitation.pending?(invitation) do
          changeset = Accounts.change_user_registration(%User{})

          render(conn, :accept,
            invitation: invitation,
            changeset: changeset,
            page_title: "Accept Invitation"
          )
        else
          message =
            if Invitation.accepted?(invitation) do
              "This invitation has already been accepted."
            else
              "This invitation has expired."
            end

          conn
          |> put_flash(:error, message)
          |> redirect(to: ~p"/")
        end
    end
  end

  def accept_invitation(conn, %{"token" => token, "user" => user_params}) do
    case Accounts.get_invitation_by_token(token) do
      nil ->
        conn
        |> put_flash(:error, "Invalid or expired invitation.")
        |> redirect(to: ~p"/")

      invitation ->
        case Accounts.accept_invitation(invitation, user_params) do
          {:ok, user} ->
            # Log invitation revocation
            AuditLog.log_event_async(:user_invitation_accepted, %{
              organization_id: invitation.organization_id,
              user_id: user.id,
              actor_type: "user",
              actor_name: "#{user.first_name} #{user.last_name}",
              outcome: "success",
              ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
              user_agent: Plug.Conn.get_req_header(conn, "user-agent") |> List.first(),
              metadata: %{
                invitation_id: invitation.id,
                invited_email: invitation.email
              }
            })

            conn
            |> put_flash(:info, "Welcome! Your account has been created successfully.")
            |> redirect(to: ~p"/login?org_slug=#{invitation.organization.slug}")

          {:error, %Ecto.Changeset{} = changeset} ->
            render(conn, :accept,
              invitation: invitation,
              changeset: changeset,
              page_title: "Accept Invitation"
            )

          {:error, :invitation_invalid} ->
            conn
            |> put_flash(:error, "This invitation is no longer valid.")
            |> redirect(to: ~p"/")
        end
    end
  end
end
