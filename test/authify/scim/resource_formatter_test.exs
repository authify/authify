defmodule Authify.SCIM.ResourceFormatterTest do
  use Authify.DataCase, async: true

  alias Authify.Accounts.{Group, User}
  alias Authify.SCIM.ResourceFormatter

  @base_url "https://authify.example.com/acme/scim/v2"

  describe "format_user/2" do
    test "formats a complete user with all fields" do
      user = %User{
        id: 123,
        external_id: "hr-12345",
        username: "jsmith",
        email: "jsmith@example.com",
        first_name: "John",
        last_name: "Smith",
        active: true,
        groups: [],
        scim_created_at: ~U[2024-01-15 10:00:00Z],
        scim_updated_at: ~U[2024-01-20 15:30:00Z],
        inserted_at: ~N[2024-01-15 10:00:00],
        updated_at: ~N[2024-01-20 15:30:00]
      }

      result = ResourceFormatter.format_user(user, @base_url)

      assert result.schemas == ["urn:ietf:params:scim:schemas:core:2.0:User"]
      assert result.id == "123"
      assert result.externalId == "hr-12345"
      assert result.userName == "jsmith"
      assert result.active == true

      assert result.name.givenName == "John"
      assert result.name.familyName == "Smith"
      assert result.name.formatted == "John Smith"

      assert [email] = result.emails
      assert email.value == "jsmith@example.com"
      assert email.primary == true
      assert email.type == "work"

      assert result.meta.resourceType == "User"
      assert result.meta.created == "2024-01-15T10:00:00Z"
      assert result.meta.lastModified == "2024-01-20T15:30:00Z"
      assert result.meta.location == "#{@base_url}/Users/123"
    end

    test "formats user with minimal fields" do
      user = %User{
        id: 456,
        external_id: nil,
        username: nil,
        email: "minimal@example.com",
        first_name: nil,
        last_name: nil,
        active: true,
        groups: [],
        scim_created_at: nil,
        scim_updated_at: nil,
        inserted_at: ~N[2024-01-15 10:00:00],
        updated_at: ~N[2024-01-15 10:00:00]
      }

      result = ResourceFormatter.format_user(user, @base_url)

      # userName falls back to email if username is nil
      assert result.userName == "minimal@example.com"

      # externalId should not be present if nil
      refute Map.has_key?(result, :externalId)

      # name should not have nil values
      refute Map.has_key?(result.name, :givenName)
      refute Map.has_key?(result.name, :familyName)
      refute Map.has_key?(result.name, :formatted)

      # meta falls back to inserted_at/updated_at
      assert result.meta.created =~ "2024-01-15"
      assert result.meta.lastModified =~ "2024-01-15"
    end

    test "formats user with groups" do
      groups = [
        %Group{id: 10, name: "Engineering"},
        %Group{id: 20, name: "Admins"}
      ]

      user = %User{
        id: 789,
        username: "jdoe",
        email: "jdoe@example.com",
        active: true,
        groups: groups,
        inserted_at: ~N[2024-01-15 10:00:00],
        updated_at: ~N[2024-01-15 10:00:00]
      }

      result = ResourceFormatter.format_user(user, @base_url)

      assert length(result.groups) == 2

      [eng, admin] = result.groups
      assert eng["value"] == "10"
      assert eng["$ref"] == "#{@base_url}/Groups/10"
      assert eng["display"] == "Engineering"

      assert admin["value"] == "20"
      assert admin["$ref"] == "#{@base_url}/Groups/20"
      assert admin["display"] == "Admins"
    end

    test "formats inactive user" do
      user = %User{
        id: 999,
        username: "inactive",
        email: "inactive@example.com",
        active: false,
        groups: [],
        inserted_at: ~N[2024-01-15 10:00:00],
        updated_at: ~N[2024-01-15 10:00:00]
      }

      result = ResourceFormatter.format_user(user, @base_url)

      assert result.active == false
    end

    test "formats name with only first name" do
      user = %User{
        id: 100,
        username: "madonna",
        email: "madonna@example.com",
        first_name: "Madonna",
        last_name: nil,
        active: true,
        groups: [],
        inserted_at: ~N[2024-01-15 10:00:00],
        updated_at: ~N[2024-01-15 10:00:00]
      }

      result = ResourceFormatter.format_user(user, @base_url)

      assert result.name.givenName == "Madonna"
      refute Map.has_key?(result.name, :familyName)
      assert result.name.formatted == "Madonna"
    end

    test "formats name with only last name" do
      user = %User{
        id: 101,
        username: "cher",
        email: "cher@example.com",
        first_name: nil,
        last_name: "Cher",
        active: true,
        groups: [],
        inserted_at: ~N[2024-01-15 10:00:00],
        updated_at: ~N[2024-01-15 10:00:00]
      }

      result = ResourceFormatter.format_user(user, @base_url)

      refute Map.has_key?(result.name, :givenName)
      assert result.name.familyName == "Cher"
      assert result.name.formatted == "Cher"
    end
  end

  describe "format_group/3" do
    test "formats a complete group with members" do
      users = [
        %User{id: 1, username: "user1", email: "user1@example.com"},
        %User{id: 2, username: "user2", email: "user2@example.com"},
        %User{id: 3, username: nil, email: "user3@example.com"}
      ]

      group = %Group{
        id: 50,
        external_id: "ldap-eng-001",
        name: "Engineering",
        users: users,
        scim_created_at: ~U[2024-01-10 08:00:00Z],
        scim_updated_at: ~U[2024-01-15 12:00:00Z],
        inserted_at: ~N[2024-01-10 08:00:00],
        updated_at: ~N[2024-01-15 12:00:00]
      }

      result = ResourceFormatter.format_group(group, 1, @base_url)

      assert result.schemas == ["urn:ietf:params:scim:schemas:core:2.0:Group"]
      assert result.id == "50"
      assert result.externalId == "ldap-eng-001"
      assert result.displayName == "Engineering"

      assert length(result.members) == 3

      [member1, member2, member3] = result.members
      assert member1["value"] == "1"
      assert member1["$ref"] == "#{@base_url}/Users/1"
      assert member1["display"] == "user1"

      assert member2["value"] == "2"
      assert member2["$ref"] == "#{@base_url}/Users/2"
      assert member2["display"] == "user2"

      # Falls back to email if no username
      assert member3["value"] == "3"
      assert member3["display"] == "user3@example.com"

      assert result.meta.resourceType == "Group"
      assert result.meta.created == "2024-01-10T08:00:00Z"
      assert result.meta.lastModified == "2024-01-15T12:00:00Z"
      assert result.meta.location == "#{@base_url}/Groups/50"
    end

    test "formats group with no members" do
      group = %Group{
        id: 60,
        external_id: nil,
        name: "Empty Group",
        users: [],
        scim_created_at: nil,
        scim_updated_at: nil,
        inserted_at: ~N[2024-01-10 08:00:00],
        updated_at: ~N[2024-01-10 08:00:00]
      }

      result = ResourceFormatter.format_group(group, 1, @base_url)

      assert result.displayName == "Empty Group"
      assert result.members == []
      refute Map.has_key?(result, :externalId)

      # Falls back to inserted_at/updated_at for meta
      assert result.meta.created =~ "2024-01-10"
    end
  end

  describe "format_list_response/4" do
    test "formats list response with multiple resources" do
      resources = [
        %{id: "1", userName: "user1"},
        %{id: "2", userName: "user2"},
        %{id: "3", userName: "user3"}
      ]

      result = ResourceFormatter.format_list_response(resources, 10, 1, 25)

      assert result.schemas == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
      assert result.totalResults == 10
      assert result.itemsPerPage == 3
      assert result.startIndex == 1
      assert result[:Resources] == resources
    end

    test "formats empty list response" do
      result = ResourceFormatter.format_list_response([], 0, 1, 25)

      assert result.totalResults == 0
      assert result.itemsPerPage == 0
      assert result.startIndex == 1
      assert result[:Resources] == []
    end

    test "formats paginated list response" do
      resources = [
        %{id: "26", userName: "user26"},
        %{id: "27", userName: "user27"}
      ]

      result = ResourceFormatter.format_list_response(resources, 100, 26, 25)

      assert result.totalResults == 100
      assert result.itemsPerPage == 2
      assert result.startIndex == 26
    end
  end

  describe "format_error/3" do
    test "formats invalid filter error" do
      result =
        ResourceFormatter.format_error(400, "invalidFilter", "The filter syntax is invalid")

      assert result.schemas == ["urn:ietf:params:scim:api:messages:2.0:Error"]
      assert result.status == "400"
      assert result.scimType == "invalidFilter"
      assert result.detail == "The filter syntax is invalid"
    end

    test "formats uniqueness error" do
      result =
        ResourceFormatter.format_error(
          409,
          "uniqueness",
          "User with externalId 'hr-123' already exists"
        )

      assert result.status == "409"
      assert result.scimType == "uniqueness"
      assert result.detail == "User with externalId 'hr-123' already exists"
    end

    test "formats not found error" do
      result = ResourceFormatter.format_error(404, "noTarget", "User not found")

      assert result.status == "404"
      assert result.scimType == "noTarget"
      assert result.detail == "User not found"
    end

    test "formats mutability error" do
      result =
        ResourceFormatter.format_error(
          400,
          "mutability",
          "Attribute 'id' is immutable and cannot be modified"
        )

      assert result.status == "400"
      assert result.scimType == "mutability"
      assert result.detail == "Attribute 'id' is immutable and cannot be modified"
    end
  end
end
