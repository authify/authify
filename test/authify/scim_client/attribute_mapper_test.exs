defmodule Authify.SCIMClient.AttributeMapperTest do
  use Authify.DataCase

  alias Authify.Accounts.{User, UserEmail}
  alias Authify.SCIMClient.AttributeMapper

  describe "map_user/2" do
    test "maps user with basic template" do
      user = %User{
        id: 1,
        username: "jdoe",
        first_name: "John",
        last_name: "Doe",
        active: true,
        external_id: "ext-123",
        emails: [
          %UserEmail{value: "john@example.com", primary: true, type: "work"}
        ]
      }

      mapping = %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => "{{username}}",
        "name" => %{
          "givenName" => "{{first_name}}",
          "familyName" => "{{last_name}}"
        },
        "emails" => [
          %{"value" => "{{primary_email}}", "primary" => true}
        ],
        "active" => "{{active}}",
        "externalId" => "{{external_id}}"
      }

      result = AttributeMapper.map_user(user, mapping)

      assert result["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:User"]
      assert result["userName"] == "jdoe"
      assert result["name"]["givenName"] == "John"
      assert result["name"]["familyName"] == "Doe"
      assert result["emails"] == [%{"value" => "john@example.com", "primary" => true}]
      assert result["active"] == "true"
      assert result["externalId"] == "ext-123"
    end

    test "handles missing optional fields" do
      user = %User{
        id: 1,
        username: "jdoe",
        first_name: nil,
        last_name: nil,
        active: true,
        external_id: nil,
        emails: []
      }

      mapping = %{
        "userName" => "{{username}}",
        "name" => %{
          "givenName" => "{{first_name}}",
          "familyName" => "{{last_name}}"
        }
      }

      result = AttributeMapper.map_user(user, mapping)

      assert result["userName"] == "jdoe"
      assert result["name"]["givenName"] == ""
      assert result["name"]["familyName"] == ""
    end

    test "handles user without primary email" do
      user = %User{
        id: 1,
        username: "jdoe",
        first_name: "John",
        last_name: "Doe",
        active: true,
        external_id: nil,
        emails: []
      }

      mapping = %{
        "userName" => "{{username}}",
        "email" => "{{primary_email}}"
      }

      result = AttributeMapper.map_user(user, mapping)

      assert result["userName"] == "jdoe"
      assert result["email"] == ""
    end

    test "interpolates values in nested structures" do
      user = %User{
        id: 1,
        username: "jdoe",
        first_name: "John",
        last_name: "Doe",
        active: true,
        external_id: nil,
        emails: [%UserEmail{value: "john@example.com", primary: true}]
      }

      mapping = %{
        "deep" => %{
          "nested" => %{
            "value" => "User: {{username}}"
          }
        }
      }

      result = AttributeMapper.map_user(user, mapping)

      assert result["deep"]["nested"]["value"] == "User: jdoe"
    end

    test "handles arrays with interpolation" do
      user = %User{
        id: 1,
        username: "jdoe",
        first_name: "John",
        last_name: "Doe",
        active: true,
        external_id: nil,
        emails: []
      }

      mapping = %{
        "roles" => ["{{username}}_admin", "{{username}}_user"]
      }

      result = AttributeMapper.map_user(user, mapping)

      assert result["roles"] == ["jdoe_admin", "jdoe_user"]
    end
  end
end
