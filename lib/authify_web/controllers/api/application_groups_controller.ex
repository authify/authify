defmodule AuthifyWeb.API.ApplicationGroupsController do
  use AuthifyWeb.API.BaseController

  alias Authify.Accounts

  @doc """
  GET /{org_slug}/api/application-groups

  List application groups in the current organization with pagination.
  Requires application_groups:read scope.
  """
  def index(conn, params) do
    case ensure_scope(conn, "application_groups:read") do
      :ok ->
        organization = conn.assigns.current_organization
        page = String.to_integer(params["page"] || "1")
        per_page = min(String.to_integer(params["per_page"] || "25"), 100)

        # Get all application groups for the organization
        groups = Accounts.list_application_groups(organization)

        # Apply pagination
        offset = (page - 1) * per_page

        paginated_groups =
          groups
          |> Enum.drop(offset)
          |> Enum.take(per_page)

        total_count = length(groups)

        render_collection_response(conn, paginated_groups,
          resource_type: "application_group",
          page_info: %{
            page: page,
            per_page: per_page,
            total: total_count
          }
        )

      {:error, response} ->
        response
    end
  end

  @doc """
  GET /{org_slug}/api/application-groups/:id

  Returns the specified application group.
  Requires application_groups:read scope.
  """
  def show(conn, %{"id" => id}) do
    case ensure_scope(conn, "application_groups:read") do
      :ok ->
        organization = conn.assigns.current_organization

        try do
          group = Accounts.get_application_group!(id)

          # Ensure group belongs to current organization
          if group.organization_id == organization.id do
            render_api_response(conn, group, resource_type: "application_group")
          else
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "Application group not found in organization"
            )
          end
        rescue
          Ecto.NoResultsError ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "Application group not found"
            )
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  POST /{org_slug}/api/application-groups

  Creates a new application group.
  Requires application_groups:write scope.
  """
  def create(conn, %{"application_group" => group_params}) do
    case ensure_scope(conn, "application_groups:write") do
      :ok ->
        organization = conn.assigns.current_organization

        case Accounts.create_application_group(organization, group_params) do
          {:ok, group} ->
            render_api_response(conn, group,
              resource_type: "application_group",
              status: :created
            )

          {:error, %Ecto.Changeset{} = changeset} ->
            render_validation_errors(conn, changeset)
        end

      {:error, response} ->
        response
    end
  end

  def create(conn, _params) do
    case ensure_scope(conn, "application_groups:write") do
      :ok ->
        render_error_response(
          conn,
          :bad_request,
          "invalid_request",
          "Request must include application_group parameters"
        )

      {:error, response} ->
        response
    end
  end

  @doc """
  PUT /{org_slug}/api/application-groups/:id

  Updates the specified application group.
  Requires application_groups:write scope.
  """
  def update(conn, %{"id" => id, "application_group" => group_params}) do
    case ensure_scope(conn, "application_groups:write") do
      :ok ->
        organization = conn.assigns.current_organization

        try do
          group = Accounts.get_application_group!(id)

          # Ensure group belongs to current organization
          if group.organization_id == organization.id do
            case Accounts.update_application_group(group, group_params) do
              {:ok, updated_group} ->
                render_api_response(conn, updated_group, resource_type: "application_group")

              {:error, %Ecto.Changeset{} = changeset} ->
                render_validation_errors(conn, changeset)
            end
          else
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "Application group not found in organization"
            )
          end
        rescue
          Ecto.NoResultsError ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "Application group not found"
            )
        end

      {:error, response} ->
        response
    end
  end

  def update(conn, %{"id" => _id}) do
    case ensure_scope(conn, "application_groups:write") do
      :ok ->
        render_error_response(
          conn,
          :bad_request,
          "invalid_request",
          "Request must include application_group parameters"
        )

      {:error, response} ->
        response
    end
  end

  @doc """
  DELETE /{org_slug}/api/application-groups/:id

  Delete an application group from the organization.
  Requires application_groups:write scope.
  """
  def delete(conn, %{"id" => id}) do
    case ensure_scope(conn, "application_groups:write") do
      :ok ->
        organization = conn.assigns.current_organization

        try do
          group = Accounts.get_application_group!(id)

          # Ensure group belongs to current organization
          if group.organization_id == organization.id do
            case Accounts.delete_application_group(group) do
              {:ok, _deleted_group} ->
                conn |> put_status(:no_content) |> json(%{})

              {:error, %Ecto.Changeset{} = changeset} ->
                render_validation_errors(conn, changeset)
            end
          else
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "Application group not found in organization"
            )
          end
        rescue
          Ecto.NoResultsError ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "Application group not found"
            )
        end

      {:error, response} ->
        response
    end
  end
end
