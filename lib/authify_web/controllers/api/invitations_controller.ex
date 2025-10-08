defmodule AuthifyWeb.API.InvitationsController do
  use AuthifyWeb.API.BaseController

  alias Authify.Accounts

  @doc """
  GET /{org_slug}/api/invitations

  List invitations in the current organization with pagination.
  Requires invitations:read scope.
  """
  def index(conn, params) do
    with :ok <- ensure_scope(conn, "invitations:read") do
      organization = conn.assigns.current_organization
      page = String.to_integer(params["page"] || "1")
      per_page = min(String.to_integer(params["per_page"] || "25"), 100)

      # Get all invitations for the organization
      invitations = Accounts.list_invitations(organization.id)

      # Apply filtering if requested
      filtered_invitations =
        case params["status"] do
          "pending" -> Enum.filter(invitations, &Authify.Accounts.Invitation.pending?/1)
          "accepted" -> Enum.filter(invitations, &Authify.Accounts.Invitation.accepted?/1)
          "expired" -> Enum.filter(invitations, &Authify.Accounts.Invitation.expired?/1)
          _ -> invitations
        end

      # Apply pagination
      offset = (page - 1) * per_page

      paginated_invitations =
        filtered_invitations
        |> Enum.drop(offset)
        |> Enum.take(per_page)

      total_count = length(filtered_invitations)

      render_collection_response(conn, paginated_invitations,
        resource_type: "invitation",
        exclude: [:token],
        page_info: %{
          page: page,
          per_page: per_page,
          total: total_count
        }
      )
    else
      {:error, response} -> response
    end
  end

  @doc """
  GET /{org_slug}/api/invitations/:id

  Returns the specified invitation.
  """
  def show(conn, %{"id" => id}) do
    with :ok <- ensure_scope(conn, "invitations:read") do
      organization = conn.assigns.current_organization

      try do
        invitation = Accounts.get_invitation!(id)

        # Ensure invitation belongs to current organization
        if invitation.organization_id == organization.id do
          render_api_response(conn, invitation,
            resource_type: "invitation",
            exclude: [:token]
          )
        else
          render_error_response(
            conn,
            :not_found,
            "resource_not_found",
            "Invitation not found in organization"
          )
        end
      rescue
        Ecto.NoResultsError ->
          render_error_response(
            conn,
            :not_found,
            "resource_not_found",
            "Invitation not found in organization"
          )
      end
    else
      {:error, response} -> response
    end
  end

  @doc """
  POST /{org_slug}/api/invitations

  Creates and sends a new invitation.
  """
  def create(conn, %{"invitation" => invitation_params}) do
    with :ok <- ensure_scope(conn, "invitations:write") do
      organization = conn.assigns.current_organization
      current_user = conn.assigns.current_user

      invitation_params_with_org =
        invitation_params
        |> Map.put("organization_id", organization.id)

      case Accounts.create_invitation_and_send_email(invitation_params_with_org, current_user) do
        {:ok, invitation} ->
          render_api_response(conn, invitation,
            resource_type: "invitation",
            exclude: [:token],
            status: :created
          )

        {:error, %Ecto.Changeset{} = changeset} ->
          render_validation_errors(conn, changeset)
      end
    else
      {:error, response} -> response
    end
  end

  def create(conn, _params) do
    with :ok <- ensure_scope(conn, "invitations:write") do
      render_error_response(
        conn,
        :bad_request,
        "invalid_request",
        "Request must include invitation parameters"
      )
    else
      {:error, response} -> response
    end
  end

  @doc """
  PUT /{org_slug}/api/invitations/:id

  Updates the specified invitation.
  """
  def update(conn, %{"id" => id, "invitation" => invitation_params}) do
    with :ok <- ensure_scope(conn, "invitations:write") do
      organization = conn.assigns.current_organization

      try do
        invitation = Accounts.get_invitation!(id)

        # Ensure invitation belongs to current organization
        if invitation.organization_id == organization.id do
          case Accounts.update_invitation(invitation, invitation_params) do
            {:ok, updated_invitation} ->
              render_api_response(conn, updated_invitation,
                resource_type: "invitation",
                exclude: [:token]
              )

            {:error, %Ecto.Changeset{} = changeset} ->
              render_validation_errors(conn, changeset)
          end
        else
          render_error_response(
            conn,
            :not_found,
            "resource_not_found",
            "Invitation not found in organization"
          )
        end
      rescue
        Ecto.NoResultsError ->
          render_error_response(
            conn,
            :not_found,
            "resource_not_found",
            "Invitation not found in organization"
          )
      end
    else
      {:error, response} -> response
    end
  end

  def update(conn, %{"id" => _id}) do
    with :ok <- ensure_scope(conn, "invitations:write") do
      render_error_response(
        conn,
        :bad_request,
        "invalid_request",
        "Request must include invitation parameters"
      )
    else
      {:error, response} -> response
    end
  end

  @doc """
  DELETE /{org_slug}/api/invitations/:id

  Delete/cancel an invitation from the organization.
  Requires invitations:write scope.
  """
  def delete(conn, %{"id" => id}) do
    with :ok <- ensure_scope(conn, "invitations:write") do
      organization = conn.assigns.current_organization

      try do
        invitation = Accounts.get_invitation!(id)

        # Ensure invitation belongs to current organization
        if invitation.organization_id == organization.id do
          case Accounts.delete_invitation(invitation) do
            {:ok, _deleted_invitation} ->
              conn |> put_status(:no_content) |> json(%{})

            {:error, %Ecto.Changeset{} = changeset} ->
              render_validation_errors(conn, changeset)
          end
        else
          render_error_response(
            conn,
            :not_found,
            "resource_not_found",
            "Invitation not found in organization"
          )
        end
      rescue
        Ecto.NoResultsError ->
          render_error_response(
            conn,
            :not_found,
            "resource_not_found",
            "Invitation not found in organization"
          )
      end
    else
      {:error, response} -> response
    end
  end
end
