defmodule Authify.SCIMClient.ProvisionerTest do
  @moduledoc """
  Tests for SCIM provisioner functionality, including feature toggle behavior.
  """
  use Authify.DataCase, async: true

  alias Authify.SCIMClient.Provisioner

  import Authify.AccountsFixtures
  import Authify.SCIMClientFixtures

  setup do
    organization = organization_fixture()
    user = user_fixture(organization: organization)
    scim_client = scim_client_fixture(organization: organization, is_active: true)

    %{
      organization: organization,
      user: user,
      scim_client: scim_client
    }
  end

  describe "provision/3 with feature toggle" do
    test "provisions when scim_outbound_provisioning_enabled is true", %{
      organization: organization,
      user: user,
      scim_client: scim_client
    } do
      # Enable SCIM outbound provisioning
      Authify.Configurations.set_organization_setting(
        organization,
        :scim_outbound_provisioning_enabled,
        true
      )

      # Provision should create a sync log
      Provisioner.provision(:created, :user, user)

      # Wait a moment for async processing
      Process.sleep(100)

      # Verify sync log was created
      {logs, _total} = Authify.SCIMClient.Client.list_sync_logs(scim_client.id)
      refute Enum.empty?(logs)
    end

    test "skips provisioning when scim_outbound_provisioning_enabled is false", %{
      organization: organization,
      user: user,
      scim_client: scim_client
    } do
      # Disable SCIM outbound provisioning (default is false)
      Authify.Configurations.set_organization_setting(
        organization,
        :scim_outbound_provisioning_enabled,
        false
      )

      # Provision should NOT create a sync log
      Provisioner.provision(:created, :user, user)

      # Wait a moment to ensure no async processing happens
      Process.sleep(100)

      # Verify NO sync log was created
      {logs, _total} = Authify.SCIMClient.Client.list_sync_logs(scim_client.id)
      assert Enum.empty?(logs)
    end

    test "skips provisioning when feature flag is not set (defaults to false)", %{
      user: user,
      scim_client: scim_client
    } do
      # Don't set the feature flag (defaults to false)

      # Provision should NOT create a sync log
      Provisioner.provision(:created, :user, user)

      # Wait a moment to ensure no async processing happens
      Process.sleep(100)

      # Verify NO sync log was created
      {logs, _total} = Authify.SCIMClient.Client.list_sync_logs(scim_client.id)
      assert Enum.empty?(logs)
    end
  end

  describe "provision/3 for different events" do
    setup %{organization: organization, scim_client: scim_client} do
      # Enable provisioning for these tests
      Authify.Configurations.set_organization_setting(
        organization,
        :scim_outbound_provisioning_enabled,
        true
      )

      %{scim_client: scim_client}
    end

    test "handles user creation events", %{user: user, scim_client: scim_client} do
      Provisioner.provision(:created, :user, user)

      Process.sleep(100)

      {logs, _total} = Authify.SCIMClient.Client.list_sync_logs(scim_client.id)
      refute Enum.empty?(logs)

      log = hd(logs)
      assert log.operation == "create"
      assert log.resource_type == "User"
    end

    test "handles user update events", %{user: user, scim_client: scim_client} do
      Provisioner.provision(:updated, :user, user)

      Process.sleep(100)

      {logs, _total} = Authify.SCIMClient.Client.list_sync_logs(scim_client.id)
      refute Enum.empty?(logs)

      log = hd(logs)
      assert log.operation == "update"
      assert log.resource_type == "User"
    end

    test "handles user deletion events", %{user: user, scim_client: scim_client} do
      Provisioner.provision(:deleted, :user, user)

      Process.sleep(100)

      {logs, _total} = Authify.SCIMClient.Client.list_sync_logs(scim_client.id)
      refute Enum.empty?(logs)

      log = hd(logs)
      assert log.operation == "delete"
      assert log.resource_type == "User"
    end
  end

  describe "provision/3 for groups" do
    setup %{organization: organization, scim_client: scim_client} do
      # Enable provisioning for these tests
      Authify.Configurations.set_organization_setting(
        organization,
        :scim_outbound_provisioning_enabled,
        true
      )

      group = group_fixture(organization: organization)
      %{group: group, scim_client: scim_client}
    end

    test "handles group creation events", %{group: group, scim_client: scim_client} do
      Provisioner.provision(:created, :group, group)

      Process.sleep(100)

      {logs, _total} = Authify.SCIMClient.Client.list_sync_logs(scim_client.id)
      refute Enum.empty?(logs)

      log = hd(logs)
      assert log.operation == "create"
      assert log.resource_type == "Group"
    end

    test "handles group update events", %{group: group, scim_client: scim_client} do
      Provisioner.provision(:updated, :group, group)

      Process.sleep(100)

      {logs, _total} = Authify.SCIMClient.Client.list_sync_logs(scim_client.id)
      refute Enum.empty?(logs)

      log = hd(logs)
      assert log.operation == "update"
      assert log.resource_type == "Group"
    end

    test "handles group deletion events", %{group: group, scim_client: scim_client} do
      Provisioner.provision(:deleted, :group, group)

      Process.sleep(100)

      {logs, _total} = Authify.SCIMClient.Client.list_sync_logs(scim_client.id)
      refute Enum.empty?(logs)

      log = hd(logs)
      assert log.operation == "delete"
      assert log.resource_type == "Group"
    end
  end
end
