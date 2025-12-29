defmodule AuthifyWeb.API.GroupsController do
  use AuthifyWeb.API.BaseController

  alias Authify.Accounts
  alias AuthifyWeb.Helpers.AuditHelper

  @doc """
  GET /{org_slug}/api/groups

  List groups in the current organization with pagination.
  Requires groups:read scope.
  """
  def index(conn, params) do
    case ensure_scope(conn, "groups:read") do
      :ok ->
        organization = conn.assigns.current_organization
        page = String.to_integer(params["page"] || "1")
        per_page = min(String.to_integer(params["per_page"] || "25"), 100)

        # Parse filtering and sorting params
        sort = params["sort"] || "name"
        order = params["order"] || "asc"
        search = params["search"]

        filter_opts = [
          sort: safe_to_atom(sort),
          order: safe_to_atom(order),
          search: search,
          page: page,
          per_page: per_page
        ]

        groups = Accounts.list_groups_filtered(organization, filter_opts)
        # Get total count by querying all groups
        all_groups = Accounts.list_groups(organization)
        total_count = length(all_groups)

        render_collection_response(conn, groups,
          resource_type: "group",
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
  GET /{org_slug}/api/groups/:id

  Get a specific group by ID.
  Requires groups:read scope.
  """
  def show(conn, %{"id" => id}) do
    case ensure_scope(conn, "groups:read") do
      :ok ->
        organization = conn.assigns.current_organization

        case safe_get_group(id, organization) do
          nil ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "Group not found in organization"
            )

          group ->
            render_api_response(conn, group, resource_type: "group")
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  POST /{org_slug}/api/groups

  Create a new group in the current organization.
  Requires groups:write scope.
  """
  def create(conn, %{"group" => group_params}) do
    case ensure_scope(conn, "groups:write") do
      :ok ->
        organization = conn.assigns.current_organization
        group_params_with_org = Map.put(group_params, "organization_id", organization.id)

        case Accounts.create_group(group_params_with_org) do
          {:ok, group} ->
            AuditHelper.log_event_async(conn, "group.created", "group", group.id, "success", %{
              "group_name" => group.name,
              "source" => "api"
            })

            render_api_response(conn, group,
              resource_type: "group",
              status: :created
            )

          {:error, %Ecto.Changeset{} = changeset} ->
            render_validation_errors(conn, changeset)
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  PUT /{org_slug}/api/groups/:id

  Update a group's information.
  Requires groups:write scope.
  """
  def update(conn, %{"id" => id, "group" => group_params}) do
    case ensure_scope(conn, "groups:write") do
      :ok ->
        organization = conn.assigns.current_organization

        case safe_get_group(id, organization) do
          nil ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "Group not found in organization"
            )

          group ->
            case Accounts.update_group(group, group_params) do
              {:ok, updated_group} ->
                AuditHelper.log_event_async(
                  conn,
                  "group.updated",
                  "group",
                  group.id,
                  "success",
                  %{
                    "group_name" => group.name,
                    "source" => "api"
                  }
                )

                render_api_response(conn, updated_group, resource_type: "group")

              {:error, %Ecto.Changeset{} = changeset} ->
                render_validation_errors(conn, changeset)
            end
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  DELETE /{org_slug}/api/groups/:id

  Delete a group from the organization.
  Requires groups:write scope.
  """
  def delete(conn, %{"id" => id}) do
    case ensure_scope(conn, "groups:write") do
      :ok ->
        organization = conn.assigns.current_organization

        case safe_get_group(id, organization) do
          nil ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "Group not found in organization"
            )

          group ->
            case Accounts.delete_group(group) do
              {:ok, _deleted_group} ->
                AuditHelper.log_event_async(
                  conn,
                  "group.deleted",
                  "group",
                  group.id,
                  "success",
                  %{
                    "group_name" => group.name,
                    "source" => "api"
                  }
                )

                send_resp(conn, :no_content, "")

              {:error, %Ecto.Changeset{} = changeset} ->
                render_validation_errors(conn, changeset)
            end
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  GET /{org_slug}/api/groups/:id/members

  Get members (users and applications) of a group.
  Requires groups:read scope.
  """
  def members(conn, %{"id" => id}) do
    case ensure_scope(conn, "groups:read") do
      :ok ->
        organization = conn.assigns.current_organization

        case safe_get_group(id, organization) do
          nil ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "Group not found in organization"
            )

          group ->
            group_with_details =
              Authify.Repo.preload(group, [:users, group_applications: [:group]])

            members = %{
              users: group_with_details.users,
              applications:
                Enum.map(group_with_details.group_applications, fn ga ->
                  %{
                    id: ga.id,
                    application_id: ga.application_id,
                    application_type: ga.application_type
                  }
                end)
            }

            json(conn, %{
              data: %{
                id: to_string(group.id),
                type: "group_members",
                attributes: members
              }
            })
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  POST /{org_slug}/api/groups/:id/users

  Add a user to a group.
  Requires groups:write scope.
  """
  def add_user(conn, %{"id" => id, "user_id" => user_id}) do
    case ensure_scope(conn, "groups:write") do
      :ok ->
        organization = conn.assigns.current_organization

        with {:ok, group} <- fetch_group(id, organization),
             {:ok, user} <- fetch_user(user_id, organization),
             {:ok, _membership} <- Accounts.add_user_to_group(user, group) do
          AuditHelper.log_event_async(conn, "group.user_added", "group", group.id, "success", %{
            "group_name" => group.name,
            "user_id" => user.id,
            "user_email" => user.email,
            "source" => "api"
          })

          send_resp(conn, :no_content, "")
        else
          {:error, :group_not_found} ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "Group not found in organization"
            )

          {:error, :user_not_found} ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "User not found in organization"
            )

          {:error, %Ecto.Changeset{} = changeset} ->
            render_validation_errors(conn, changeset)
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  DELETE /{org_slug}/api/groups/:id/users/:user_id

  Remove a user from a group.
  Requires groups:write scope.
  """
  def remove_user(conn, %{"id" => id, "user_id" => user_id}) do
    case ensure_scope(conn, "groups:write") do
      :ok ->
        organization = conn.assigns.current_organization

        with {:ok, group} <- fetch_group(id, organization),
             {:ok, user} <- fetch_user(user_id, organization) do
          {count, _} = Accounts.remove_user_from_group(user, group)

          if count > 0 do
            AuditHelper.log_event_async(
              conn,
              "group.user_removed",
              "group",
              group.id,
              "success",
              %{
                "group_name" => group.name,
                "user_id" => user.id,
                "user_email" => user.email,
                "source" => "api"
              }
            )

            send_resp(conn, :no_content, "")
          else
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "User is not a member of this group"
            )
          end
        else
          {:error, :group_not_found} ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "Group not found in organization"
            )

          {:error, :user_not_found} ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "User not found in organization"
            )
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  POST /{org_slug}/api/groups/:id/applications

  Add an application to a group.
  Requires groups:write scope.
  """
  def add_application(conn, %{
        "id" => id,
        "application_id" => app_id,
        "application_type" => app_type
      }) do
    case ensure_scope(conn, "groups:write") do
      :ok ->
        organization = conn.assigns.current_organization

        case safe_get_group(id, organization) do
          nil ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "Group not found in organization"
            )

          group ->
            case Accounts.add_application_to_group(group, app_id, app_type) do
              {:ok, _member} ->
                AuditHelper.log_event_async(
                  conn,
                  "group.application_added",
                  "group",
                  group.id,
                  "success",
                  %{
                    "group_name" => group.name,
                    "application_id" => app_id,
                    "application_type" => app_type,
                    "source" => "api"
                  }
                )

                send_resp(conn, :no_content, "")

              {:error, %Ecto.Changeset{} = changeset} ->
                render_validation_errors(conn, changeset)
            end
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  DELETE /{org_slug}/api/groups/:id/applications/:member_id

  Remove an application from a group.
  Requires groups:write scope.
  """
  def remove_application(conn, %{"id" => id, "member_id" => member_id}) do
    case ensure_scope(conn, "groups:write") do
      :ok ->
        organization = conn.assigns.current_organization

        case safe_get_group(id, organization) do
          nil ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "Group not found in organization"
            )

          group ->
            case Accounts.remove_application_from_group(group, member_id) do
              {count, _} when count > 0 ->
                AuditHelper.log_event_async(
                  conn,
                  "group.application_removed",
                  "group",
                  group.id,
                  "success",
                  %{
                    "group_name" => group.name,
                    "member_id" => member_id,
                    "source" => "api"
                  }
                )

                send_resp(conn, :no_content, "")

              _ ->
                render_error_response(
                  conn,
                  :not_found,
                  "resource_not_found",
                  "Application is not a member of this group"
                )
            end
        end

      {:error, response} ->
        response
    end
  end

  # Private helper functions

  # Safely convert string to atom, only for known valid values
  defp safe_to_atom(string)
       when string in ~w(name description is_active inserted_at updated_at asc desc) do
    String.to_existing_atom(string)
  end

  defp safe_to_atom(string) when is_binary(string), do: :name
  defp safe_to_atom(value), do: value

  defp safe_get_group(id, organization) do
    Accounts.get_group!(id, organization)
  rescue
    Ecto.NoResultsError -> nil
  end

  defp fetch_group(id, organization) do
    case safe_get_group(id, organization) do
      nil -> {:error, :group_not_found}
      group -> {:ok, group}
    end
  end

  defp fetch_user(id, organization) do
    case Accounts.get_user_in_organization(id, organization.id) do
      nil -> {:error, :user_not_found}
      user -> {:ok, user}
    end
  end
end
