defmodule AuthifyTest.SCIMConsumerTest do
  @moduledoc false

  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  alias AuthifyTest.OAuthClient
  alias AuthifyTest.SCIMConsumer

  # All tests get a valid token via PAT. Unit tests focus on consumer behavior;
  # the integration test exercises the full OAuth2 client_credentials scope flow.
  setup do
    org = organization_fixture()
    admin = user_fixture(organization: org, role: "admin")

    {:ok, token_string} =
      OAuthClient.create_pat(admin, org, scopes: Authify.Scopes.pat_scopes())

    consumer = SCIMConsumer.new(build_conn(), org, token: token_string)

    {:ok,
     %{
       org: org,
       admin: admin,
       consumer: consumer,
       token: token_string
     }}
  end

  defp authenticated_consumer(org) do
    admin = user_fixture(organization: org, role: "admin")
    {:ok, token} = OAuthClient.create_pat(admin, org, scopes: Authify.Scopes.pat_scopes())
    SCIMConsumer.new(build_conn(), org, token: token)
  end

  # ── Struct ───────────────────────────────────────

  describe "new/3" do
    test "creates a consumer struct with conn, org, and token" do
      org = organization_fixture()
      consumer = SCIMConsumer.new(build_conn(), org, token: "fake-token")

      assert consumer.org == org
      assert consumer.token == "fake-token"
    end
  end

  # ── Request Construction ─────────────────────────

  describe "create_user/2" do
    test "POST /Users sends correct User schemas URI" do
      org = organization_fixture()
      consumer = authenticated_consumer(org)

      assert {:ok, map} =
               SCIMConsumer.create_user(consumer, %{
                 userName: "schemas-#{System.monotonic_time()}",
                 name: %{givenName: "Test", familyName: "User"},
                 emails: [%{value: "test@example.com", primary: true}]
               })

      assert map["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:User"]
      assert is_binary(map["id"])
      assert map["meta"]["resourceType"] == "User"
    end

    test "returns error for invalid token" do
      org = organization_fixture()
      consumer = SCIMConsumer.new(build_conn(), org, token: "invalid-token")

      assert {:error, {:unexpected_status, 401, _body}} =
               SCIMConsumer.create_user(consumer, %{
                 userName: "nobody-#{System.monotonic_time()}",
                 name: %{givenName: "No", familyName: "Body"},
                 emails: [%{value: "nobody@example.com"}]
               })
    end
  end

  describe "create_group/2" do
    test "POST /Groups sends correct Group schemas URI" do
      org = organization_fixture()
      consumer = authenticated_consumer(org)

      name = "grp-schemas-#{System.monotonic_time()}"

      assert {:ok, map} = SCIMConsumer.create_group(consumer, name)
      assert map["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:Group"]
      assert is_binary(map["id"])
      assert map["displayName"] == name
    end
  end

  # ── PATCH Envelope ───────────────────────────────

  describe "patch_user/3" do
    test "PATCH body is correctly enveloped with PatchOp schema" do
      org = organization_fixture()
      consumer = authenticated_consumer(org)

      user_name = "patch-env-#{System.monotonic_time()}"

      {:ok, user} =
        SCIMConsumer.create_user(consumer, %{
          userName: user_name,
          name: %{givenName: "Patch", familyName: "User"},
          emails: [%{value: "patch@example.com"}]
        })

      assert {:ok, patched} =
               SCIMConsumer.patch_user(consumer, user["id"], [
                 %{"op" => "replace", "path" => "active", "value" => false}
               ])

      assert patched["active"] == false
    end
  end

  # ── Response Validation ──────────────────────────

  describe "validate_resource/1" do
    test "rejects resource missing id field" do
      invalid = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "meta" => %{"resourceType" => "User", "location" => "http://example.com/Users/1"}
      }

      assert {:error, {:invalid_response, missing}} =
               SCIMConsumer.validate_resource(invalid)

      assert "id" in missing
    end

    test "rejects resource missing meta.location" do
      invalid = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id" => "1",
        "meta" => %{"resourceType" => "User"}
      }

      assert {:error, {:invalid_response, missing}} =
               SCIMConsumer.validate_resource(invalid)

      assert "meta.location" in missing
    end

    test "rejects resource missing meta field entirely" do
      invalid = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id" => "1"
      }

      assert {:error, {:invalid_response, missing}} =
               SCIMConsumer.validate_resource(invalid)

      assert "meta.resourceType" in missing
      assert "meta.location" in missing
    end

    test "rejects resource with empty schemas list" do
      invalid = %{
        "schemas" => [],
        "id" => "1",
        "meta" => %{"resourceType" => "User", "location" => "http://example.com/Users/1"}
      }

      assert {:error, {:invalid_response, missing}} =
               SCIMConsumer.validate_resource(invalid)

      assert "schemas" in missing
    end

    test "accepts valid resource with all required fields" do
      valid = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id" => "1",
        "meta" => %{"resourceType" => "User", "location" => "http://example.com/Users/1"},
        "userName" => "test"
      }

      assert {:ok, ^valid} = SCIMConsumer.validate_resource(valid)
    end
  end

  describe "validate_list_response/1" do
    test "rejects response missing required ListResponse fields" do
      invalid = %{"totalResults" => 0}

      assert {:error, {:invalid_response, missing}} =
               SCIMConsumer.validate_list_response(invalid)

      assert "startIndex" in missing
      assert "itemsPerPage" in missing
      assert "Resources" in missing
    end

    test "accepts valid ListResponse" do
      valid = %{
        "totalResults" => 1,
        "startIndex" => 1,
        "itemsPerPage" => 25,
        "Resources" => [
          %{
            "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id" => "1",
            "meta" => %{"resourceType" => "User", "location" => "http://example.com/Users/1"}
          }
        ]
      }

      assert {:ok, ^valid} = SCIMConsumer.validate_list_response(valid)
    end
  end

  # ── ETag State Management ────────────────────────

  describe "ETag round-trip" do
    test "ETag from create is sent as If-Match on update" do
      org = organization_fixture()
      consumer = authenticated_consumer(org)

      user_name = "etag-rt-#{System.monotonic_time()}"

      {:ok, user} =
        SCIMConsumer.create_user(consumer, %{
          userName: user_name,
          name: %{givenName: "Etag", familyName: "Round"},
          emails: [%{value: "etag@example.com"}]
        })

      # update_user/3 automatically sends If-Match from cached ETag
      assert {:ok, updated} =
               SCIMConsumer.update_user(consumer, user["id"], %{active: false})

      assert updated["active"] == false
    end

    test "stale ETag returns {:error, :conflict}" do
      org = organization_fixture()
      consumer = authenticated_consumer(org)

      user_name = "etag-stale-#{System.monotonic_time()}"

      {:ok, user} =
        SCIMConsumer.create_user(consumer, %{
          userName: user_name,
          name: %{givenName: "Stale", familyName: "Etag"},
          emails: [%{value: "stale@example.com"}]
        })

      # Corrupt the cached ETag so the server will reject it
      Process.put(
        {:scim_etag, org.id, "Users", user["id"]},
        "W/\"00000000-0-0\""
      )

      assert {:error, :conflict} =
               SCIMConsumer.update_user(consumer, user["id"], %{active: false})
    end
  end

  # ── User Lifecycle ───────────────────────────────

  describe "fetch_user/2" do
    test "returns {:ok, user} for existing user", %{consumer: consumer} do
      {:ok, user} =
        SCIMConsumer.create_user(consumer, %{
          userName: "fetch-#{System.monotonic_time()}",
          name: %{givenName: "Fetch", familyName: "User"},
          emails: [%{value: "fetch@example.com"}]
        })

      assert {:ok, fetched} = SCIMConsumer.fetch_user(consumer, user["id"])
      assert fetched["id"] == user["id"]
    end

    test "returns {:error, :not_found} for nonexistent ID", %{consumer: consumer} do
      assert {:error, :not_found} = SCIMConsumer.fetch_user(consumer, "nonexistent-id")
    end
  end

  describe "update_user/3" do
    test "returns {:error, :not_found} for nonexistent user", %{consumer: consumer} do
      assert {:error, :not_found} = SCIMConsumer.update_user(consumer, "nope", %{active: false})
    end
  end

  describe "delete_user/2" do
    test "returns :ok for existing user", %{consumer: consumer} do
      {:ok, user} =
        SCIMConsumer.create_user(consumer, %{
          userName: "del-#{System.monotonic_time()}",
          name: %{givenName: "Del", familyName: "User"},
          emails: [%{value: "del@example.com"}]
        })

      assert :ok = SCIMConsumer.delete_user(consumer, user["id"])
    end

    test "returns {:error, :not_found} for nonexistent ID", %{consumer: consumer} do
      assert {:error, :not_found} = SCIMConsumer.delete_user(consumer, "nonexistent")
    end

    test "user remains fetchable with active: false after deletion", %{consumer: consumer} do
      {:ok, user} =
        SCIMConsumer.create_user(consumer, %{
          userName: "del-soft-#{System.monotonic_time()}",
          name: %{givenName: "Soft", familyName: "Delete"},
          emails: [%{value: "soft@example.com"}]
        })

      assert :ok = SCIMConsumer.delete_user(consumer, user["id"])

      assert {:ok, restored} = SCIMConsumer.fetch_user(consumer, user["id"])
      assert restored["active"] == false
    end
  end

  # ── List ─────────────────────────────────────────

  describe "list_users/2" do
    test "returns valid ListResponse", %{consumer: consumer} do
      assert {:ok, list_resp} = SCIMConsumer.list_users(consumer)
      assert is_map(list_resp)
      assert is_integer(list_resp["totalResults"])
      assert is_integer(list_resp["startIndex"])
      assert is_integer(list_resp["itemsPerPage"])
      assert is_list(list_resp["Resources"])
    end

    test "supports filter option (snake_case → SCIM query param)", %{consumer: consumer} do
      user_name = "filter-list-#{System.monotonic_time()}"

      SCIMConsumer.create_user(consumer, %{
        userName: user_name,
        name: %{givenName: "Filter", familyName: "List"},
        emails: [%{value: "filter@example.com"}]
      })

      assert {:ok, list_resp} =
               SCIMConsumer.list_users(consumer,
                 filter: ~s(userName sw "filter-list"),
                 count: 10,
                 start_index: 1
               )

      assert list_resp["totalResults"] >= 1
    end
  end

  describe "list_groups/2" do
    test "returns valid ListResponse", %{consumer: consumer} do
      assert {:ok, list_resp} = SCIMConsumer.list_groups(consumer)
      assert is_map(list_resp)
      assert is_integer(list_resp["totalResults"])
    end
  end

  # ── Group Member Management ──────────────────────

  describe "update_group_members/3" do
    test "member add and remove via PATCH envelope" do
      org = organization_fixture()
      consumer = authenticated_consumer(org)

      user_name = "member-uv-#{System.monotonic_time()}"

      {:ok, user} =
        SCIMConsumer.create_user(consumer, %{
          userName: user_name,
          name: %{givenName: "Member", familyName: "User"},
          emails: [%{value: "member@example.com"}]
        })

      group_name = "grp-members-#{System.monotonic_time()}"

      {:ok, group} = SCIMConsumer.create_group(consumer, group_name)

      assert {:ok, with_member} =
               SCIMConsumer.update_group_members(consumer, group["id"],
                 add: [user["id"]],
                 remove: []
               )

      members = with_member["members"] || []
      assert match?([_], members)

      assert {:ok, without_member} =
               SCIMConsumer.update_group_members(consumer, group["id"],
                 add: [],
                 remove: [user["id"]]
               )

      updated_members = without_member["members"] || []
      assert updated_members == []
    end
  end
end
