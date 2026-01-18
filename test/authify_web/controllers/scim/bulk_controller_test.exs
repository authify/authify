defmodule AuthifyWeb.SCIM.BulkControllerTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  setup %{conn: conn} do
    organization = organization_fixture()
    admin_user = user_fixture(organization: organization, role: "admin")

    conn =
      conn
      |> assign(:current_organization, organization)
      |> assign(:current_user, admin_user)
      |> assign(:api_authenticated, true)
      |> assign(:current_scopes, ["scim:write"])

    {:ok, conn: conn, organization: organization, admin_user: admin_user}
  end

  describe "POST /scim/v2/Bulk" do
    test "creates multiple users in a single request", %{conn: conn, organization: organization} do
      bulk_request = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
        "Operations" => [
          %{
            "method" => "POST",
            "path" => "/Users",
            "bulkId" => "user1",
            "data" => %{
              "userName" => "alice@example.com",
              "name" => %{"givenName" => "Alice", "familyName" => "Smith"},
              "active" => true
            }
          },
          %{
            "method" => "POST",
            "path" => "/Users",
            "bulkId" => "user2",
            "data" => %{
              "userName" => "bob@example.com",
              "name" => %{"givenName" => "Bob", "familyName" => "Jones"},
              "active" => true
            }
          }
        ]
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Bulk", bulk_request)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert response["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:BulkResponse"]
      assert length(response["Operations"]) == 2

      # Verify both operations succeeded
      Enum.each(response["Operations"], fn op ->
        assert op["status"] == "201"
        assert op["location"]
        assert op["response"]["userName"]
      end)

      # Verify the userNames in the response
      usernames = Enum.map(response["Operations"], fn op -> op["response"]["userName"] end)
      assert "alice@example.com" in usernames
      assert "bob@example.com" in usernames
    end

    test "creates multiple groups in a single request", %{conn: conn, organization: organization} do
      bulk_request = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
        "Operations" => [
          %{
            "method" => "POST",
            "path" => "/Groups",
            "bulkId" => "group1",
            "data" => %{"displayName" => "Engineering"}
          },
          %{
            "method" => "POST",
            "path" => "/Groups",
            "bulkId" => "group2",
            "data" => %{"displayName" => "Sales"}
          }
        ]
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Bulk", bulk_request)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert length(response["Operations"]) == 2

      Enum.each(response["Operations"], fn op ->
        assert op["status"] == "201"
      end)
    end

    test "supports mixed operations (create, update, delete)", %{
      conn: conn,
      organization: organization
    } do
      # Create a user first
      existing_user = user_fixture(organization: organization, email: "existing@example.com")

      bulk_request = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
        "Operations" => [
          %{
            "method" => "POST",
            "path" => "/Users",
            "bulkId" => "newuser",
            "data" => %{
              "userName" => "new@example.com",
              "active" => true
            }
          },
          %{
            "method" => "PUT",
            "path" => "/Users/#{existing_user.id}",
            "data" => %{
              "userName" => "updated@example.com",
              "active" => true
            }
          },
          %{
            "method" => "DELETE",
            "path" => "/Users/#{existing_user.id}"
          }
        ]
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Bulk", bulk_request)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert length(response["Operations"]) == 3
      assert Enum.at(response["Operations"], 0)["status"] == "201"
      assert Enum.at(response["Operations"], 1)["status"] == "200"
      assert Enum.at(response["Operations"], 2)["status"] == "204"
    end

    test "supports bulkId references in paths", %{conn: conn, organization: organization} do
      bulk_request = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
        "Operations" => [
          %{
            "method" => "POST",
            "path" => "/Groups",
            "bulkId" => "group1",
            "data" => %{"displayName" => "Engineering"}
          },
          %{
            "method" => "PUT",
            "path" => "/Groups/bulkId:group1",
            "data" => %{"displayName" => "Engineering Team"}
          }
        ]
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Bulk", bulk_request)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert length(response["Operations"]) == 2
      # First operation creates the group
      assert Enum.at(response["Operations"], 0)["status"] == "201"
      # Second operation updates it using bulkId reference
      assert Enum.at(response["Operations"], 1)["status"] == "200"
    end

    test "respects failOnErrors threshold", %{conn: conn, organization: organization} do
      bulk_request = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
        "failOnErrors" => 1,
        "Operations" => [
          %{
            "method" => "POST",
            "path" => "/Users",
            "bulkId" => "user1",
            # Missing required fields - will fail
            "data" => %{}
          },
          %{
            "method" => "POST",
            "path" => "/Users",
            "bulkId" => "user2",
            "data" => %{"userName" => "valid@example.com"}
          },
          %{
            "method" => "POST",
            "path" => "/Users",
            "bulkId" => "user3",
            "data" => %{"userName" => "another@example.com"}
          }
        ]
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Bulk", bulk_request)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert length(response["Operations"]) == 3

      # First operation should fail
      assert Enum.at(response["Operations"], 0)["status"] == "400"

      # Subsequent operations should fail due to failOnErrors threshold
      assert Enum.at(response["Operations"], 1)["status"] == "412"
      assert Enum.at(response["Operations"], 1)["response"]["detail"] =~ "failOnErrors"
      assert Enum.at(response["Operations"], 2)["status"] == "412"
    end

    test "continues processing when failOnErrors is not reached", %{
      conn: conn,
      organization: organization
    } do
      bulk_request = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
        "failOnErrors" => 2,
        "Operations" => [
          %{
            "method" => "POST",
            "path" => "/Users",
            # Will fail
            "data" => %{}
          },
          %{
            "method" => "POST",
            "path" => "/Users",
            # Should succeed
            "data" => %{"userName" => "valid@example.com"}
          }
        ]
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Bulk", bulk_request)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert length(response["Operations"]) == 2
      assert Enum.at(response["Operations"], 0)["status"] == "400"
      assert Enum.at(response["Operations"], 1)["status"] == "201"
    end

    test "returns error for invalid bulk request schema", %{
      conn: conn,
      organization: organization
    } do
      bulk_request = %{
        "schemas" => ["urn:wrong:schema"],
        "Operations" => []
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Bulk", bulk_request)

      assert conn.status == 400
      response = json_response(conn, 400)
      assert response["scimType"] == "invalidSyntax"
    end

    test "returns error for missing Operations field", %{conn: conn, organization: organization} do
      bulk_request = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"]
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Bulk", bulk_request)

      assert conn.status == 400
      response = json_response(conn, 400)
      assert response["detail"] =~ "Operations"
    end

    test "returns error for too many operations", %{conn: conn, organization: organization} do
      operations =
        Enum.map(1..1001, fn i ->
          %{
            "method" => "POST",
            "path" => "/Users",
            "data" => %{"userName" => "user#{i}@example.com"}
          }
        end)

      bulk_request = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
        "Operations" => operations
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Bulk", bulk_request)

      assert conn.status == 413
      response = json_response(conn, 413)
      assert response["detail"] =~ "Too many operations"
    end

    test "returns error for unsupported method", %{conn: conn, organization: organization} do
      bulk_request = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
        "Operations" => [
          %{
            "method" => "PATCH",
            "path" => "/Users/123",
            "data" => %{}
          }
        ]
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Bulk", bulk_request)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert length(response["Operations"]) == 1
      assert Enum.at(response["Operations"], 0)["status"] == "400"
      assert Enum.at(response["Operations"], 0)["response"]["detail"] =~ "Unsupported method"
    end

    test "returns error for invalid path", %{conn: conn, organization: organization} do
      bulk_request = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
        "Operations" => [
          %{
            "method" => "POST",
            "path" => "/InvalidResource",
            "data" => %{}
          }
        ]
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Bulk", bulk_request)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert length(response["Operations"]) == 1
      assert Enum.at(response["Operations"], 0)["status"] == "400"
      assert Enum.at(response["Operations"], 0)["response"]["detail"] =~ "Invalid path"
    end

    test "enforces multi-tenant isolation", %{conn: conn} do
      # Create a user in a different organization
      other_org = organization_fixture()
      other_user = user_fixture(organization: other_org, email: "other@example.com")

      bulk_request = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
        "Operations" => [
          %{
            "method" => "DELETE",
            "path" => "/Users/#{other_user.id}"
          }
        ]
      }

      conn = post(conn, "/#{conn.assigns.current_organization.slug}/scim/v2/Bulk", bulk_request)

      assert conn.status == 200
      response = json_response(conn, 200)

      # Should return 404 (not found) instead of deleting
      assert Enum.at(response["Operations"], 0)["status"] == "404"
    end

    test "requires scim:write scope", %{conn: conn, organization: organization} do
      conn =
        conn
        |> assign(:current_scopes, ["scim:read"])

      bulk_request = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
        "Operations" => []
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Bulk", bulk_request)

      assert conn.status == 403
    end

    test "preserves bulkId in response for each operation", %{
      conn: conn,
      organization: organization
    } do
      bulk_request = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
        "Operations" => [
          %{
            "method" => "POST",
            "path" => "/Users",
            "bulkId" => "myuser1",
            "data" => %{"userName" => "test@example.com"}
          },
          %{
            "method" => "POST",
            "path" => "/Groups",
            "bulkId" => "mygroup1",
            "data" => %{"displayName" => "Test Group"}
          }
        ]
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Bulk", bulk_request)

      assert conn.status == 200
      response = json_response(conn, 200)

      assert Enum.at(response["Operations"], 0)["bulkId"] == "myuser1"
      assert Enum.at(response["Operations"], 1)["bulkId"] == "mygroup1"
    end

    test "blocks access when SCIM inbound provisioning is disabled", %{
      conn: conn,
      organization: organization
    } do
      # Disable SCIM for the organization
      Authify.Configurations.set_organization_setting(
        organization,
        :scim_inbound_provisioning_enabled,
        false
      )

      bulk_request = %{
        "schemas" => ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
        "Operations" => [
          %{
            "method" => "POST",
            "path" => "/Users",
            "data" => %{"userName" => "test@example.com"}
          }
        ]
      }

      conn = post(conn, "/#{organization.slug}/scim/v2/Bulk", bulk_request)

      assert conn.status == 404
      response = json_response(conn, 404)
      assert response["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
      assert response["detail"] =~ "SCIM provisioning is not enabled"
    end
  end
end
