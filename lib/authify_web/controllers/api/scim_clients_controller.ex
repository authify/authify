defmodule AuthifyWeb.API.ScimClientsController do
  use AuthifyWeb.API.BaseController

  alias Authify.SCIMClient.{Client, Provisioner}
  alias AuthifyWeb.Helpers.AuditHelper

  @doc """
  GET /{org_slug}/api/scim-clients

  Returns a paginated list of SCIM clients for the organization.
  Requires scim_clients:read or scim_clients:write scope.
  """
  def index(conn, params) do
    scopes = conn.assigns[:current_scopes] || []
    has_read = "scim_clients:read" in scopes or "scim_clients:write" in scopes

    if has_read do
      organization = conn.assigns.current_organization
      page = String.to_integer(params["page"] || "1")
      per_page = String.to_integer(params["per_page"] || "25")

      {scim_clients, total} =
        Client.list_scim_clients(organization.id, page: page, per_page: per_page)

      page_info = %{
        page: page,
        per_page: per_page,
        total: total
      }

      render_collection_response(conn, scim_clients,
        resource_type: "scim_client",
        page_info: page_info,
        exclude: [:auth_credential]
      )
    else
      render_error_response(
        conn,
        :forbidden,
        "insufficient_scope",
        "Requires scim_clients:read or scim_clients:write scope"
      )
    end
  end

  @doc """
  GET /{org_slug}/api/scim-clients/:id

  Get a specific SCIM client by ID.
  Requires scim_clients:read or scim_clients:write scope.
  """
  def show(conn, %{"id" => id}) do
    scopes = conn.assigns[:current_scopes] || []
    has_read = "scim_clients:read" in scopes or "scim_clients:write" in scopes

    if has_read do
      organization = conn.assigns.current_organization

      try do
        scim_client = Client.get_scim_client!(id, organization.id)

        render_api_response(conn, scim_client,
          resource_type: "scim_client",
          exclude: [:auth_credential]
        )
      rescue
        Ecto.NoResultsError ->
          render_error_response(
            conn,
            :not_found,
            "resource_not_found",
            "SCIM client not found in organization"
          )
      end
    else
      render_error_response(
        conn,
        :forbidden,
        "insufficient_scope",
        "Requires scim_clients:read or scim_clients:write scope"
      )
    end
  end

  @doc """
  POST /{org_slug}/api/scim-clients

  Create a new SCIM client in the current organization.
  Requires scim_clients:write scope.
  """
  def create(conn, %{"scim_client" => scim_client_params}) do
    case ensure_scope(conn, "scim_clients:write") do
      :ok ->
        organization = conn.assigns.current_organization

        case Client.create_scim_client(scim_client_params, organization.id) do
          {:ok, scim_client} ->
            # Log audit event
            AuditHelper.log_event_async(
              conn,
              :scim_client_created,
              "scim_client",
              scim_client.id,
              "success",
              %{
                provider: scim_client.name,
                base_url: scim_client.base_url,
                auth_type: scim_client.auth_type
              }
            )

            render_api_response(conn, scim_client,
              resource_type: "scim_client",
              status: :created,
              exclude: [:auth_credential]
            )

          {:error, changeset} ->
            render_validation_errors(conn, changeset)
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  PUT /{org_slug}/api/scim-clients/:id

  Update a SCIM client's configuration.
  Requires scim_clients:write scope.
  """
  def update(conn, %{"id" => id, "scim_client" => scim_client_params}) do
    case ensure_scope(conn, "scim_clients:write") do
      :ok ->
        organization = conn.assigns.current_organization

        try do
          scim_client = Client.get_scim_client!(id, organization.id)

          # Remove empty credential to preserve existing value
          params =
            if scim_client_params["auth_credential"] in [nil, ""] do
              Map.delete(scim_client_params, "auth_credential")
            else
              scim_client_params
            end

          case Client.update_scim_client(scim_client, params) do
            {:ok, updated_scim_client} ->
              # Log audit event
              AuditHelper.log_event_async(
                conn,
                :scim_client_updated,
                "scim_client",
                updated_scim_client.id,
                "success",
                %{
                  provider: updated_scim_client.name,
                  is_active: updated_scim_client.is_active,
                  changes: Map.keys(scim_client_params)
                }
              )

              render_api_response(conn, updated_scim_client,
                resource_type: "scim_client",
                exclude: [:auth_credential]
              )

            {:error, changeset} ->
              render_validation_errors(conn, changeset)
          end
        rescue
          Ecto.NoResultsError ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "SCIM client not found in organization"
            )
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  DELETE /{org_slug}/api/scim-clients/:id

  Delete a SCIM client from the organization.
  Requires scim_clients:write scope.
  """
  def delete(conn, %{"id" => id}) do
    case ensure_scope(conn, "scim_clients:write") do
      :ok ->
        organization = conn.assigns.current_organization

        try do
          scim_client = Client.get_scim_client!(id, organization.id)

          case Client.delete_scim_client(scim_client) do
            {:ok, _scim_client} ->
              # Log audit event
              AuditHelper.log_event_async(
                conn,
                :scim_client_deleted,
                "scim_client",
                scim_client.id,
                "success",
                %{
                  provider: scim_client.name,
                  base_url: scim_client.base_url
                }
              )

              send_resp(conn, :no_content, "")

            {:error, changeset} ->
              render_validation_errors(conn, changeset)
          end
        rescue
          Ecto.NoResultsError ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "SCIM client not found in organization"
            )
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  POST /{org_slug}/api/scim-clients/:id/sync

  Trigger a manual sync for a SCIM client.
  Requires scim_clients:write scope.
  """
  def trigger_sync(conn, %{"scim_client_id" => id}) do
    case ensure_scope(conn, "scim_clients:write") do
      :ok ->
        organization = conn.assigns.current_organization

        try do
          scim_client = Client.get_scim_client!(id, organization.id)

          # Trigger full sync (async in production, sync in tests)
          Provisioner.async_full_sync(scim_client)

          # Log audit event
          AuditHelper.log_event_async(
            conn,
            :scim_client_manual_sync_triggered,
            "scim_client",
            scim_client.id,
            "success",
            %{
              provider: scim_client.name,
              sync_users: scim_client.sync_users,
              sync_groups: scim_client.sync_groups
            }
          )

          json(conn, %{
            status: "sync_triggered",
            message: "Full sync initiated for SCIM client"
          })
        rescue
          Ecto.NoResultsError ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "SCIM client not found in organization"
            )
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  GET /{org_slug}/api/scim-clients/:id/logs

  Get sync logs for a specific SCIM client.
  Requires scim_clients:read or scim_clients:write scope.
  """
  def logs(conn, %{"scim_client_id" => id} = params) do
    scopes = conn.assigns[:current_scopes] || []
    has_read = "scim_clients:read" in scopes or "scim_clients:write" in scopes

    if has_read do
      organization = conn.assigns.current_organization

      try do
        scim_client = Client.get_scim_client!(id, organization.id)
        page = String.to_integer(params["page"] || "1")
        per_page = String.to_integer(params["per_page"] || "50")

        {logs, total} = Client.list_sync_logs(scim_client.id, page: page, per_page: per_page)

        page_info = %{
          page: page,
          per_page: per_page,
          total: total
        }

        render_collection_response(conn, logs,
          resource_type: "scim_sync_log",
          page_info: page_info
        )
      rescue
        Ecto.NoResultsError ->
          render_error_response(
            conn,
            :not_found,
            "resource_not_found",
            "SCIM client not found in organization"
          )
      end
    else
      render_error_response(
        conn,
        :forbidden,
        "insufficient_scope",
        "Requires scim_clients:read or scim_clients:write scope"
      )
    end
  end
end
