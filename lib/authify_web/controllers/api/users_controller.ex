defmodule AuthifyWeb.API.UsersController do
  use AuthifyWeb.API.BaseController

  alias Authify.Accounts

  @doc """
  GET /{org_slug}/api/users

  List users in the current organization with pagination.
  Requires users:read scope.
  """
  def index(conn, params) do
    with :ok <- ensure_scope(conn, "users:read") do
      organization = conn.assigns.current_organization
      page = String.to_integer(params["page"] || "1")
      per_page = min(String.to_integer(params["per_page"] || "25"), 100)

      users = Accounts.list_users(organization.id, page: page, per_page: per_page)
      total_count = Accounts.count_users(organization.id)

      render_collection_response(conn, users,
        resource_type: "user",
        exclude: [:password_hash, :email_verified_at, :password_reset_token],
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
  GET /{org_slug}/api/users/:id

  Get a specific user by ID.
  Requires users:read scope.
  """
  def show(conn, %{"id" => id}) do
    with :ok <- ensure_scope(conn, "users:read") do
      organization = conn.assigns.current_organization

      case Accounts.get_user_in_organization(id, organization.id) do
        nil ->
          render_error_response(
            conn,
            :not_found,
            "resource_not_found",
            "User not found in organization"
          )

        user ->
          render_api_response(conn, user,
            resource_type: "user",
            exclude: [:password_hash, :email_verified_at, :password_reset_token]
          )
      end
    else
      {:error, response} -> response
    end
  end

  @doc """
  POST /{org_slug}/api/users

  Create a new user in the current organization.
  Requires users:write scope.
  """
  def create(conn, %{"user" => user_params}) do
    with :ok <- ensure_scope(conn, "users:write") do
      organization = conn.assigns.current_organization
      user_params_with_org = Map.put(user_params, "organization_id", organization.id)

      case Accounts.create_user(user_params_with_org) do
        {:ok, user} ->
          render_api_response(conn, user,
            resource_type: "user",
            exclude: [:password_hash, :email_verified_at, :password_reset_token],
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
    with :ok <- ensure_scope(conn, "users:write") do
      render_error_response(
        conn,
        :bad_request,
        "invalid_request",
        "Request must include user parameters"
      )
    else
      {:error, response} -> response
    end
  end

  @doc """
  PUT /{org_slug}/api/users/:id

  Update a user's profile information.
  Requires users:write scope.
  """
  def update(conn, %{"id" => id, "user" => user_params}) do
    with :ok <- ensure_scope(conn, "users:write") do
      organization = conn.assigns.current_organization

      case Accounts.get_user_in_organization(id, organization.id) do
        nil ->
          render_error_response(
            conn,
            :not_found,
            "resource_not_found",
            "User not found in organization"
          )

        user ->
          case Accounts.update_user(user, user_params) do
            {:ok, updated_user} ->
              render_api_response(conn, updated_user,
                resource_type: "user",
                exclude: [:password_hash, :email_verified_at, :password_reset_token]
              )

            {:error, %Ecto.Changeset{} = changeset} ->
              render_validation_errors(conn, changeset)
          end
      end
    else
      {:error, response} -> response
    end
  end

  def update(conn, %{"id" => _id}) do
    with :ok <- ensure_scope(conn, "users:write") do
      render_error_response(
        conn,
        :bad_request,
        "invalid_request",
        "Request must include user parameters"
      )
    else
      {:error, response} -> response
    end
  end

  @doc """
  DELETE /{org_slug}/api/users/:id

  Delete a user from the organization.
  Requires users:write scope.
  """
  def delete(conn, %{"id" => id}) do
    with :ok <- ensure_scope(conn, "users:write") do
      organization = conn.assigns.current_organization
      current_user = conn.assigns.current_user

      case Accounts.get_user_in_organization(id, organization.id) do
        nil ->
          render_error_response(
            conn,
            :not_found,
            "resource_not_found",
            "User not found in organization"
          )

        user ->
          # Prevent self-deletion
          if user.id == current_user.id do
            render_error_response(
              conn,
              :forbidden,
              "invalid_operation",
              "You cannot delete your own account"
            )
          else
            case Accounts.delete_user(user) do
              {:ok, _deleted_user} ->
                conn |> put_status(:no_content) |> json(%{})

              {:error, %Ecto.Changeset{} = changeset} ->
                render_validation_errors(conn, changeset)
            end
          end
      end
    else
      {:error, response} -> response
    end
  end

  @doc """
  PUT /{org_slug}/api/users/:id/role

  Update a user's role in the organization.
  Requires users:write scope.
  """
  def update_role(conn, %{"id" => id, "role" => role}) do
    with :ok <- ensure_scope(conn, "users:write") do
      organization = conn.assigns.current_organization

      case Accounts.get_user_in_organization(id, organization.id) do
        nil ->
          render_error_response(
            conn,
            :not_found,
            "resource_not_found",
            "User not found in organization"
          )

        user ->
          if role in ["user", "admin"] do
            case Accounts.update_user_role(user, role) do
              {:ok, updated_user} ->
                render_api_response(conn, updated_user,
                  resource_type: "user",
                  exclude: [:password_hash, :email_verified_at, :password_reset_token]
                )

              {:error, changeset} ->
                render_validation_errors(conn, changeset)
            end
          else
            render_error_response(
              conn,
              :unprocessable_entity,
              "validation_failed",
              "Invalid role specified",
              %{"role" => ["must be either 'user' or 'admin'"]}
            )
          end
      end
    else
      {:error, response} -> response
    end
  end

  def update_role(conn, %{"id" => _id}) do
    with :ok <- ensure_scope(conn, "users:write") do
      render_error_response(
        conn,
        :bad_request,
        "invalid_request",
        "Request must include role parameter"
      )
    else
      {:error, response} -> response
    end
  end
end
