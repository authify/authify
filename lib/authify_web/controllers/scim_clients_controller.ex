defmodule AuthifyWeb.ScimClientsController do
  use AuthifyWeb, :controller

  alias Authify.AuditLog
  alias Authify.SCIMClient.{Client, HTTPClient, Provisioner, ScimClient}

  def index(conn, _params) do
    organization = conn.assigns.current_organization
    scim_clients = Client.list_scim_clients(organization.id)

    provisioning_enabled =
      Authify.Configurations.get_organization_setting(
        organization,
        :scim_outbound_provisioning_enabled
      )

    render(conn, :index,
      scim_clients: scim_clients,
      provisioning_enabled: provisioning_enabled
    )
  end

  def show(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    scim_client = Client.get_scim_client!(id, organization.id)

    # Get recent sync logs for this client
    {logs, _total} = Client.list_sync_logs(scim_client.id, page: 1, per_page: 10)

    provisioning_enabled =
      Authify.Configurations.get_organization_setting(
        organization,
        :scim_outbound_provisioning_enabled
      )

    render(conn, :show,
      scim_client: scim_client,
      sync_logs: logs,
      organization: organization,
      provisioning_enabled: provisioning_enabled
    )
  end

  def new(conn, _params) do
    organization = conn.assigns.current_organization
    changeset = Client.change_scim_client(%ScimClient{})

    render(conn, :new,
      changeset: changeset,
      organization: organization
    )
  end

  def create(conn, %{"scim_client" => scim_client_params}) do
    organization = conn.assigns.current_organization

    case Client.create_scim_client(scim_client_params, organization.id) do
      {:ok, scim_client} ->
        # Log SCIM client creation
        log_scim_client_event(conn, :scim_client_created, scim_client, %{
          provider: scim_client.name,
          base_url: scim_client.base_url
        })

        conn
        |> put_flash(:info, "SCIM client created successfully.")
        |> redirect(to: ~p"/#{organization.slug}/scim_clients/#{scim_client}")

      {:error, %Ecto.Changeset{} = changeset} ->
        render(conn, :new, changeset: changeset)
    end
  end

  def edit(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    scim_client = Client.get_scim_client!(id, organization.id)
    changeset = Client.change_scim_client(scim_client)

    render(conn, :edit,
      scim_client: scim_client,
      changeset: changeset,
      organization: organization
    )
  end

  def update(conn, %{"id" => id, "scim_client" => scim_client_params}) do
    organization = conn.assigns.current_organization
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
        # Log SCIM client update
        log_scim_client_event(conn, :scim_client_updated, updated_scim_client, %{
          provider: updated_scim_client.name,
          is_active: updated_scim_client.is_active
        })

        conn
        |> put_flash(:info, "SCIM client updated successfully.")
        |> redirect(to: ~p"/#{organization.slug}/scim_clients/#{updated_scim_client}")

      {:error, %Ecto.Changeset{} = changeset} ->
        render(conn, :edit,
          scim_client: scim_client,
          changeset: changeset,
          organization: organization
        )
    end
  end

  def delete(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    scim_client = Client.get_scim_client!(id, organization.id)
    {:ok, _scim_client} = Client.delete_scim_client(scim_client)

    # Log SCIM client deletion
    log_scim_client_event(conn, :scim_client_deleted, scim_client, %{
      provider: scim_client.name,
      base_url: scim_client.base_url
    })

    conn
    |> put_flash(:info, "SCIM client deleted successfully.")
    |> redirect(to: ~p"/#{organization.slug}/scim_clients")
  end

  def logs(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    scim_client = Client.get_scim_client!(id, organization.id)

    # Get paginated sync logs
    page = (conn.params["page"] || "1") |> String.to_integer()
    {logs, total} = Client.list_sync_logs(scim_client.id, page: page, per_page: 50)

    render(conn, :logs,
      scim_client: scim_client,
      sync_logs: logs,
      total: total,
      page: page,
      per_page: 50
    )
  end

  def test_connection(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    scim_client = Client.get_scim_client!(id, organization.id)

    case HTTPClient.test_connection(scim_client) do
      {:ok, message} ->
        # Log successful connection test
        log_scim_client_event(conn, :scim_client_connection_tested, scim_client, %{
          result: "success",
          message: message
        })

        conn
        |> put_flash(:info, "Connection test successful: #{message}")
        |> redirect(to: ~p"/#{organization.slug}/scim_clients/#{scim_client}")

      {:error, error_message} ->
        # Log failed connection test
        log_scim_client_event(conn, :scim_client_connection_tested, scim_client, %{
          result: "failure",
          error: error_message
        })

        conn
        |> put_flash(:error, "Connection test failed: #{error_message}")
        |> redirect(to: ~p"/#{organization.slug}/scim_clients/#{scim_client}")
    end
  end

  def manual_sync(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    scim_client = Client.get_scim_client!(id, organization.id)

    # Trigger async full sync
    Task.Supervisor.start_child(Authify.TaskSupervisor, fn ->
      Provisioner.full_sync(scim_client)
    end)

    # Log sync trigger
    log_scim_client_event(conn, :scim_client_manual_sync_triggered, scim_client, %{
      sync_users: scim_client.sync_users,
      sync_groups: scim_client.sync_groups
    })

    conn
    |> put_flash(
      :info,
      "Manual sync started. Check the sync logs to monitor progress."
    )
    |> redirect(to: ~p"/#{organization.slug}/scim_clients/#{scim_client}")
  end

  # Private helper functions

  defp log_scim_client_event(conn, event_type, scim_client, metadata) do
    organization = conn.assigns.current_organization
    current_user = conn.assigns.current_user

    AuditLog.log_event_async(event_type, %{
      organization_id: organization.id,
      actor_type: "user",
      actor_id: current_user.id,
      actor_name: "#{current_user.first_name} #{current_user.last_name}",
      resource_type: "scim_client",
      resource_id: scim_client.id,
      outcome: "success",
      ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
      user_agent: Plug.Conn.get_req_header(conn, "user-agent") |> List.first(),
      metadata:
        Map.merge(metadata, %{
          client_name: scim_client.name,
          client_id: scim_client.id
        })
    })
  end
end
