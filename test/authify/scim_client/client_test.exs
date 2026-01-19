defmodule Authify.SCIMClient.ClientTest do
  use Authify.DataCase

  alias Authify.SCIMClient.Client
  alias Authify.SCIMClient.{ExternalId, ScimClient, SyncLog}

  import Authify.AccountsFixtures
  import Authify.SCIMClientFixtures

  describe "scim_clients" do
    @invalid_attrs %{
      name: nil,
      base_url: nil,
      auth_type: nil,
      organization_id: nil
    }

    test "list_scim_clients/1 returns all scim_clients for an organization" do
      organization = organization_fixture()
      scim_client = scim_client_fixture(organization: organization)
      clients = Client.list_scim_clients(organization.id)
      assert length(clients) == 1
      assert hd(clients).id == scim_client.id
    end

    test "list_active_scim_clients/2 returns only active clients with sync enabled" do
      organization = organization_fixture()
      active_client = scim_client_fixture(organization: organization, is_active: true)

      _inactive_client =
        scim_client_fixture(organization: organization, name: "Inactive", is_active: false)

      _no_sync_client =
        scim_client_fixture(organization: organization, name: "No Sync", sync_users: false)

      clients = Client.list_active_scim_clients(organization.id, :user)
      assert length(clients) == 1
      assert hd(clients).id == active_client.id
    end

    test "get_scim_client!/2 returns the scim_client with given id and organization" do
      organization = organization_fixture()
      scim_client = scim_client_fixture(organization: organization)
      found_client = Client.get_scim_client!(scim_client.id, organization.id)
      assert found_client.id == scim_client.id
      assert found_client.name == scim_client.name
    end

    test "create_scim_client/2 with valid data creates a scim_client" do
      organization = organization_fixture()

      default_mapping =
        Jason.encode!(%{
          "user" => %{
            "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName" => "{{username}}"
          }
        })

      valid_attrs = %{
        "name" => "Test Client",
        "description" => "A test client",
        "base_url" => "https://example.com/scim/v2",
        "auth_type" => "bearer",
        "auth_credential" => "secret-token",
        "attribute_mapping" => default_mapping,
        "is_active" => true,
        "sync_users" => true,
        "sync_groups" => false
      }

      assert {:ok, %ScimClient{} = client} =
               Client.create_scim_client(valid_attrs, organization.id)

      assert client.name == "Test Client"
      assert client.description == "A test client"
      assert client.base_url == "https://example.com/scim/v2"
      assert client.auth_type == "bearer"
      assert client.is_active == true
      assert client.sync_users == true
      assert client.sync_groups == false
      assert client.organization_id == organization.id
    end

    test "create_scim_client/2 with invalid data returns error changeset" do
      organization = organization_fixture()

      assert {:error, %Ecto.Changeset{}} =
               Client.create_scim_client(@invalid_attrs, organization.id)
    end

    test "create_scim_client/2 requires auth_credential for bearer auth" do
      organization = organization_fixture()

      attrs = %{
        "name" => "Test",
        "base_url" => "https://example.com/scim/v2",
        "auth_type" => "bearer"
      }

      assert {:error, %Ecto.Changeset{} = changeset} =
               Client.create_scim_client(attrs, organization.id)

      assert "can't be blank" in errors_on(changeset).auth_credential
    end

    test "create_scim_client/2 requires auth_username and auth_credential for basic auth" do
      organization = organization_fixture()

      attrs = %{
        "name" => "Test",
        "base_url" => "https://example.com/scim/v2",
        "auth_type" => "basic"
      }

      assert {:error, %Ecto.Changeset{} = changeset} =
               Client.create_scim_client(attrs, organization.id)

      assert "can't be blank" in errors_on(changeset).auth_username
      assert "can't be blank" in errors_on(changeset).auth_credential
    end

    test "update_scim_client/2 with valid data updates the scim_client" do
      organization = organization_fixture()
      scim_client = scim_client_fixture(organization: organization)

      update_attrs = %{
        "name" => "Updated Name",
        "description" => "Updated description",
        "is_active" => false
      }

      assert {:ok, %ScimClient{} = updated} = Client.update_scim_client(scim_client, update_attrs)
      assert updated.name == "Updated Name"
      assert updated.description == "Updated description"
      assert updated.is_active == false
    end

    test "update_scim_client/2 with invalid data returns error changeset" do
      organization = organization_fixture()
      scim_client = scim_client_fixture(organization: organization)
      assert {:error, %Ecto.Changeset{}} = Client.update_scim_client(scim_client, @invalid_attrs)
      found = Client.get_scim_client!(scim_client.id, organization.id)
      assert found.name == scim_client.name
    end

    test "delete_scim_client/1 deletes the scim_client" do
      organization = organization_fixture()
      scim_client = scim_client_fixture(organization: organization)
      assert {:ok, %ScimClient{}} = Client.delete_scim_client(scim_client)

      assert_raise Ecto.NoResultsError, fn ->
        Client.get_scim_client!(scim_client.id, organization.id)
      end
    end

    test "change_scim_client/1 returns a scim_client changeset" do
      scim_client = scim_client_fixture()
      assert %Ecto.Changeset{} = Client.change_scim_client(scim_client)
    end
  end

  describe "sync_logs" do
    test "create_sync_log/1 creates a sync log" do
      scim_client = scim_client_fixture()

      attrs = %{
        scim_client_id: scim_client.id,
        resource_type: "User",
        resource_id: 123,
        operation: "create",
        status: "pending"
      }

      assert {:ok, %SyncLog{} = log} = Client.create_sync_log(attrs)
      assert log.scim_client_id == scim_client.id
      assert log.resource_type == "User"
      assert log.resource_id == 123
      assert log.operation == "create"
      assert log.status == "pending"
    end

    test "update_sync_log_success/4 updates log to success status" do
      sync_log = sync_log_fixture()
      response_body = %{"id" => "ext-123", "userName" => "test"}

      assert {:ok, %SyncLog{} = updated} =
               Client.update_sync_log_success(sync_log, 201, response_body, "ext-123")

      assert updated.status == "success"
      assert updated.http_status == 201
      assert updated.response_body != nil
    end

    test "update_sync_log_failure/3 updates log to failed status" do
      sync_log = sync_log_fixture()
      next_retry = DateTime.add(DateTime.utc_now(), 300, :second)

      assert {:ok, %SyncLog{} = updated} =
               Client.update_sync_log_failure(
                 sync_log,
                 {:http_error, 500, "Server error"},
                 next_retry
               )

      assert updated.status == "failed"
      assert updated.error_message =~ "HTTP 500"
      assert updated.retry_count == 1
      assert updated.next_retry_at != nil
    end

    test "get_retriable_sync_logs/0 returns logs ready for retry" do
      scim_client = scim_client_fixture()
      past_time = DateTime.add(DateTime.utc_now(), -60, :second)

      # Create a failed log with retry time in the past
      {:ok, log} =
        Client.create_sync_log(%{
          scim_client_id: scim_client.id,
          resource_type: "User",
          resource_id: 1,
          operation: "create",
          status: "failed",
          retry_count: 1,
          next_retry_at: past_time
        })

      logs = Client.get_retriable_sync_logs()
      refute Enum.empty?(logs)
      assert Enum.any?(logs, fn l -> l.id == log.id end)
    end

    test "list_sync_logs/2 returns paginated logs for a client" do
      scim_client = scim_client_fixture()
      _log1 = sync_log_fixture(scim_client: scim_client)
      _log2 = sync_log_fixture(scim_client: scim_client, resource_id: 2)

      {logs, total} = Client.list_sync_logs(scim_client.id, page: 1, per_page: 10)
      assert length(logs) == 2
      assert total == 2
    end
  end

  describe "external_ids" do
    test "store_external_id/4 stores an external ID" do
      scim_client = scim_client_fixture()

      assert {:ok, %ExternalId{} = external_id} =
               Client.store_external_id(scim_client.id, "User", 123, "ext-123")

      assert external_id.scim_client_id == scim_client.id
      assert external_id.resource_type == "User"
      assert external_id.resource_id == 123
      assert external_id.external_id == "ext-123"
    end

    test "store_external_id/4 updates existing external ID on conflict" do
      scim_client = scim_client_fixture()

      {:ok, _} = Client.store_external_id(scim_client.id, "User", 123, "ext-123")
      {:ok, updated} = Client.store_external_id(scim_client.id, "User", 123, "ext-456")

      assert updated.external_id == "ext-456"
    end

    test "get_external_id/3 retrieves an external ID" do
      scim_client = scim_client_fixture()
      {:ok, _} = Client.store_external_id(scim_client.id, "User", 123, "ext-123")

      assert {:ok, "ext-123"} = Client.get_external_id(scim_client.id, :user, 123)
    end

    test "get_external_id/3 returns error when not found" do
      scim_client = scim_client_fixture()
      assert {:error, :not_found} = Client.get_external_id(scim_client.id, :user, 999)
    end

    test "delete_external_ids/2 removes all external IDs for a resource" do
      scim_client1 = scim_client_fixture()
      scim_client2 = scim_client_fixture(name: "Client 2")

      {:ok, _} = Client.store_external_id(scim_client1.id, "User", 123, "ext-123")
      {:ok, _} = Client.store_external_id(scim_client2.id, "User", 123, "ext-456")

      {count, _} = Client.delete_external_ids(:user, 123)
      assert count == 2

      assert {:error, :not_found} = Client.get_external_id(scim_client1.id, :user, 123)
      assert {:error, :not_found} = Client.get_external_id(scim_client2.id, :user, 123)
    end
  end
end
