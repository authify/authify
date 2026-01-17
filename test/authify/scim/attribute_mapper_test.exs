defmodule Authify.SCIM.AttributeMapperTest do
  use ExUnit.Case, async: true

  alias Authify.SCIM.AttributeMapper

  describe "scim_to_ecto_field/2" do
    test "maps known user attributes" do
      assert {:ok, :id} = AttributeMapper.scim_to_ecto_field("id", :user)
      assert {:ok, :username} = AttributeMapper.scim_to_ecto_field("userName", :user)
      assert {:ok, :first_name} = AttributeMapper.scim_to_ecto_field("name.givenName", :user)
      assert {:ok, :last_name} = AttributeMapper.scim_to_ecto_field("name.familyName", :user)
      assert {:ok, :email} = AttributeMapper.scim_to_ecto_field("emails", :user)

      assert {:ok, :scim_updated_at} =
               AttributeMapper.scim_to_ecto_field("meta.lastModified", :user)
    end

    test "maps known group attributes" do
      assert {:ok, :external_id} = AttributeMapper.scim_to_ecto_field("externalId", :group)
      assert {:ok, :name} = AttributeMapper.scim_to_ecto_field("displayName", :group)
      assert {:ok, :scim_created_at} = AttributeMapper.scim_to_ecto_field("meta.created", :group)
    end

    test "rejects unknown attributes" do
      assert {:error, :unknown_attribute} = AttributeMapper.scim_to_ecto_field("unknown", :user)
      assert {:error, :unknown_attribute} = AttributeMapper.scim_to_ecto_field("other", :group)
    end
  end

  describe "ecto_to_scim_attribute/2" do
    test "converts user fields back to SCIM attribute names" do
      assert AttributeMapper.ecto_to_scim_attribute(:username, :user) == "userName"
      assert AttributeMapper.ecto_to_scim_attribute(:first_name, :user) == "name.givenName"
      assert AttributeMapper.ecto_to_scim_attribute(:scim_created_at, :user) == "meta.created"
    end

    test "converts group fields back to SCIM attribute names" do
      assert AttributeMapper.ecto_to_scim_attribute(:name, :group) == "displayName"

      assert AttributeMapper.ecto_to_scim_attribute(:scim_updated_at, :group) ==
               "meta.lastModified"
    end
  end

  describe "known_scim_attributes/1" do
    test "returns allowlisted user attributes" do
      attributes = AttributeMapper.known_scim_attributes(:user)

      assert "userName" in attributes
      assert "emails" in attributes
      assert length(attributes) > 5
    end

    test "returns allowlisted group attributes" do
      attributes = AttributeMapper.known_scim_attributes(:group)

      assert "displayName" in attributes
      assert "externalId" in attributes
    end
  end

  describe "valid_scim_attribute?/2" do
    test "returns true for allowlisted attributes" do
      assert AttributeMapper.valid_scim_attribute?("userName", :user)
      assert AttributeMapper.valid_scim_attribute?("displayName", :group)
    end

    test "returns false for unknown attributes" do
      refute AttributeMapper.valid_scim_attribute?("foo", :user)
      refute AttributeMapper.valid_scim_attribute?("bar", :group)
    end
  end
end
