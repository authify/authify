defmodule Authify.SCIMClientFixtures do
  @moduledoc """
  This module defines test helpers for creating entities via the
  `Authify.SCIMClient` context.
  """

  alias Authify.SCIMClient.Client

  @doc """
  Generate a SCIM client.
  """
  def scim_client_fixture(attrs \\ %{}) do
    # Convert to map if keyword list
    attrs = if Keyword.keyword?(attrs), do: Enum.into(attrs, %{}), else: attrs

    organization = attrs[:organization] || Authify.AccountsFixtures.organization_fixture()

    default_mapping =
      Jason.encode!(%{
        "user" => %{
          "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
          "userName" => "{{username}}",
          "name" => %{
            "givenName" => "{{first_name}}",
            "familyName" => "{{last_name}}"
          },
          "emails" => [%{"value" => "{{primary_email}}", "primary" => true}],
          "active" => "{{active}}"
        }
      })

    # Convert to string keys and set defaults
    attrs = Map.drop(attrs, [:organization])

    attrs =
      Map.merge(
        %{
          "name" => "Test SCIM Client",
          "description" => "A test SCIM client",
          "base_url" => "https://test-scim-fixture.local/scim/v2",
          "auth_type" => "bearer",
          "auth_credential" => "test-bearer-token-secret",
          "attribute_mapping" => default_mapping,
          "is_active" => true,
          "sync_users" => false,
          "sync_groups" => false
        },
        stringify_keys(attrs)
      )

    {:ok, scim_client} = Client.create_scim_client(attrs, organization.id)
    scim_client
  end

  defp stringify_keys(map) when is_map(map) do
    map
    |> Enum.map(fn {k, v} -> {to_string(k), v} end)
    |> Enum.into(%{})
  end

  @doc """
  Generate a sync log.
  """
  def sync_log_fixture(attrs \\ %{}) do
    scim_client = attrs[:scim_client] || scim_client_fixture()

    attrs =
      Enum.into(attrs, %{
        scim_client_id: scim_client.id,
        resource_type: "User",
        resource_id: 1,
        operation: "create",
        status: "pending"
      })

    {:ok, sync_log} = Client.create_sync_log(attrs)
    sync_log
  end

  @doc """
  Generate an external ID.
  """
  def external_id_fixture(attrs \\ %{}) do
    scim_client = attrs[:scim_client] || scim_client_fixture()

    attrs =
      Enum.into(attrs, %{
        scim_client_id: scim_client.id,
        resource_type: "User",
        resource_id: 1,
        external_id: "ext-123"
      })

    scim_client_id = attrs.scim_client_id
    resource_type = attrs.resource_type
    resource_id = attrs.resource_id
    external_id = attrs.external_id

    {:ok, external_id_record} =
      Client.store_external_id(scim_client_id, resource_type, resource_id, external_id)

    external_id_record
  end
end
