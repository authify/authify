defmodule Authify.SCIMClient.EventHandler do
  @moduledoc """
  Subscribes to user/group change events and triggers SCIM provisioning.
  Started by Application supervisor.
  """
  use GenServer

  require Logger

  alias Authify.SCIMClient.Provisioner

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    # Subscribe to SCIM provisioning events for all organizations
    # The topic pattern is "scim_provisioning:org_<org_id>"
    # Note: We subscribe dynamically when events are published
    {:ok, %{}}
  end

  @impl true
  def handle_info({event, resource_type, resource}, state)
      when event in [:created, :updated, :deleted] and
             resource_type in [:user, :group] do
    # Ensure we're subscribed to this organization's events
    subscribe_to_org(resource.organization_id)

    # Async provision to all active SCIM clients for this org
    Task.Supervisor.start_child(
      Authify.TaskSupervisor,
      fn -> Provisioner.provision(event, resource_type, resource) end
    )

    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    # Ignore unknown messages
    {:noreply, state}
  end

  # Private functions

  defp subscribe_to_org(org_id) do
    topic = "scim_provisioning:org_#{org_id}"

    # Subscribe returns :ok or {:error, {:already_registered, pid}}
    # We don't care if we're already subscribed
    Phoenix.PubSub.subscribe(Authify.PubSub, topic)
    :ok
  rescue
    _ -> :ok
  end
end
