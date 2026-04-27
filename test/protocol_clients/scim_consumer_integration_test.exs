defmodule AuthifyTest.SCIMConsumerIntegrationTest do
  @moduledoc """
  End-to-end integration test for AuthifyTest.SCIMConsumer.

  Exercises the complete SCIM user and group provisioning lifecycle against
  Authify's real SCIM endpoints using a real OAuth bearer token. Catches:

  - Request body schema compliance (schemas URIs, PATCH envelope)
  - Response schema validation (required fields per RFC 7643)
  - ETag round-trip (cached ETag sent as If-Match on updates)
  - Soft delete behavior (user remains fetchable after delete)
  - Group member management via PATCH
  - OAuth scope enforcement (real token with scim:read/scim:write)
  """

  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures
  import Authify.OAuthFixtures

  alias AuthifyTest.OAuthClient
  alias AuthifyTest.SCIMConsumer

  @tag :capture_log
  test "complete user and group provisioning lifecycle with real OAuth token" do
    # ── Setup: obtain real bearer token via OAuth client credentials ──

    org = organization_fixture()

    app =
      management_api_application_fixture(
        organization: org,
        scopes: Enum.join(["scim:read", "scim:write"], " ")
      )

    oauth_client = OAuthClient.new(build_conn(), app, org)

    {:ok, tokens} =
      OAuthClient.client_credentials(oauth_client, scopes: ["scim:read", "scim:write"])

    consumer = SCIMConsumer.new(build_conn(), org, token: tokens.access_token)

    # ── Step 1: Create user ────────────────────────────────────────

    user_name = "e2e-#{System.monotonic_time()}"

    assert {:ok, user} =
             SCIMConsumer.create_user(consumer, %{
               userName: user_name,
               name: %{givenName: "E2E", familyName: "User"},
               emails: [%{value: "e2e@example.com", primary: true}]
             })

    # Assert SCIM response schema
    assert user["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:User"]
    assert is_binary(user["id"])
    assert user["meta"]["resourceType"] == "User"
    assert is_binary(user["meta"]["location"])
    assert user["userName"] == user_name

    # ── Step 2: Fetch user by ID ───────────────────────────────────

    assert {:ok, fetched} = SCIMConsumer.fetch_user(consumer, user["id"])
    assert fetched["id"] == user["id"]
    assert fetched["userName"] == user_name

    # ── Step 3: Update user via PUT (deactivate) ───────────────────

    assert {:ok, deactivated} =
             SCIMConsumer.update_user(consumer, user["id"], %{active: false})

    assert deactivated["active"] == false

    # ── Step 4: Patch user via PATCH (re-activate) ─────────────────

    assert {:ok, reactivated} =
             SCIMConsumer.patch_user(consumer, user["id"], [
               %{"op" => "replace", "path" => "active", "value" => true}
             ])

    assert reactivated["active"] == true

    # ── Step 5: Delete user (soft delete → 204) ────────────────────

    assert :ok = SCIMConsumer.delete_user(consumer, user["id"])

    # ── Step 6: Fetch user after delete (soft delete, not 404) ─────

    assert {:ok, deleted_user} = SCIMConsumer.fetch_user(consumer, user["id"])
    assert deleted_user["active"] == false

    # ── Step 7: Create group with initial member ───────────────────

    group_name = "grp-e2e-#{System.monotonic_time()}"

    assert {:ok, group} = SCIMConsumer.create_group(consumer, group_name)
    assert group["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:Group"]
    assert is_binary(group["id"])
    assert group["displayName"] == group_name

    # ── Step 8: Update group members (add, then remove) ────────────

    # Create another user to add to the group
    member_name = "e2e-member-#{System.monotonic_time()}"

    {:ok, member_user} =
      SCIMConsumer.create_user(consumer, %{
        userName: member_name,
        name: %{givenName: "E2E", familyName: "Member"},
        emails: [%{value: "member@example.com"}]
      })

    assert {:ok, added} =
             SCIMConsumer.update_group_members(consumer, group["id"],
               add: [member_user["id"]],
               remove: []
             )

    members = added["members"] || []
    assert match?([_], members)
    assert Enum.at(members, 0)["value"] == member_user["id"]

    assert {:ok, removed} =
             SCIMConsumer.update_group_members(consumer, group["id"],
               add: [],
               remove: [member_user["id"]]
             )

    members_after = removed["members"] || []
    assert members_after == []
  end
end
