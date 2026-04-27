defmodule AuthifyWeb.SCIMIntegrationTest do
  @moduledoc """
  Integration test demonstrating the IntegrationCase base template.

  Exercises a SCIM user provisioning lifecycle using SCIMConsumer and
  OAuthClient, both aliased automatically by IntegrationCase.
  """

  use AuthifyWeb.IntegrationCase

  import Authify.OAuthFixtures

  @tag :capture_log
  test "user provisioning lifecycle: create → fetch → deactivate → delete", %{
    conn: conn,
    org: org
  } do
    # Obtain a real Management API bearer token via client credentials
    app =
      management_api_application_fixture(
        organization: org,
        scopes: Enum.join(["scim:read", "scim:write"], " ")
      )

    oauth_client = OAuthClient.new(conn, app, org)

    assert {:ok, tokens} =
             OAuthClient.client_credentials(oauth_client, scopes: ["scim:read", "scim:write"])

    consumer = SCIMConsumer.new(build_conn(), org, token: tokens.access_token)

    # Create user
    user_name = "scim-integration-#{System.unique_integer([:positive])}"

    assert {:ok, scim_user} =
             SCIMConsumer.create_user(consumer, %{
               userName: user_name,
               name: %{givenName: "SCIM", familyName: "Test"},
               emails: [%{value: "#{user_name}@example.com", primary: true}]
             })

    assert scim_user["userName"] == user_name
    assert scim_user["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:User"]
    assert is_binary(scim_user["id"])

    # Fetch user by ID
    assert {:ok, fetched} = SCIMConsumer.fetch_user(consumer, scim_user["id"])
    assert fetched["id"] == scim_user["id"]

    # Deactivate via PATCH
    assert {:ok, deactivated} =
             SCIMConsumer.patch_user(consumer, scim_user["id"], [
               %{"op" => "replace", "path" => "active", "value" => false}
             ])

    assert deactivated["active"] == false

    # Delete (soft-delete → 204)
    assert :ok = SCIMConsumer.delete_user(consumer, scim_user["id"])

    # After soft-delete the user is still fetchable but marked inactive
    assert {:ok, deleted_user} = SCIMConsumer.fetch_user(consumer, scim_user["id"])
    assert deleted_user["active"] == false
  end
end
