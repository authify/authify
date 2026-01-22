defmodule Authify.Accounts.SCIMTest do
  use Authify.DataCase, async: true

  import Authify.AccountsFixtures

  alias Authify.Accounts
  alias Authify.Accounts.User

  describe "list_users_scim/2 and count_users_scim/2" do
    setup do
      organization = organization_fixture()

      {:ok, _} =
        Accounts.create_user_scim(
          scim_user_attrs(%{username: "alpha", active: true}),
          organization.id
        )

      {:ok, _} =
        Accounts.create_user_scim(
          scim_user_attrs(%{username: "beta", active: false}),
          organization.id
        )

      {:ok, _} =
        Accounts.create_user_scim(
          scim_user_attrs(%{username: "gamma", active: true}),
          organization.id
        )

      %{organization: organization}
    end

    test "paginates results and enforces max page size", %{organization: organization} do
      {:ok, users} = Accounts.list_users_scim(organization.id, page: 1, per_page: 2)
      assert length(users) == 2

      {:ok, users_page_2} = Accounts.list_users_scim(organization.id, page: 2, per_page: 2)
      assert length(users_page_2) == 1

      {:ok, users_max} = Accounts.list_users_scim(organization.id, per_page: 500)
      assert length(users_max) <= 100
    end

    test "sorts by userName ascending and descending", %{organization: organization} do
      {:ok, asc_users} =
        Accounts.list_users_scim(organization.id, sort_by: "userName", sort_order: "ascending")

      assert Enum.map(asc_users, & &1.username) == Enum.sort(Enum.map(asc_users, & &1.username))

      {:ok, desc_users} =
        Accounts.list_users_scim(organization.id, sort_by: "userName", sort_order: "descending")

      assert Enum.map(desc_users, & &1.username) ==
               Enum.sort(Enum.map(desc_users, & &1.username), :desc)
    end

    test "filters using SCIM filter string", %{organization: organization} do
      {:ok, users} =
        Accounts.list_users_scim(organization.id,
          filter: "userName sw \"a\"",
          sort_by: "userName"
        )

      assert length(users) == 1
      assert hd(users).username == "alpha"

      {:ok, count} = Accounts.count_users_scim(organization.id, filter: "active eq true")
      assert count == 2
    end

    test "propagates filter errors" do
      organization = organization_fixture()

      assert {:error, _} = Accounts.list_users_scim(organization.id, filter: "invalid filter")
      assert {:error, _} = Accounts.count_users_scim(organization.id, filter: "invalid filter")
    end
  end

  describe "list_groups_scim/2 and count_groups_scim/2" do
    setup do
      organization = organization_fixture()

      {:ok, group_a} = Accounts.create_group_scim(%{name: "Engineering"}, organization.id)
      {:ok, group_b} = Accounts.create_group_scim(%{name: "Support"}, organization.id)
      {:ok, group_c} = Accounts.create_group_scim(%{name: "Finance"}, organization.id)

      %{organization: organization, group_a: group_a, group_b: group_b, group_c: group_c}
    end

    test "paginates and sorts groups", %{organization: organization} do
      {:ok, groups} = Accounts.list_groups_scim(organization.id, sort_by: "displayName")
      assert Enum.map(groups, & &1.name) == ["Engineering", "Finance", "Support"]

      {:ok, desc_groups} =
        Accounts.list_groups_scim(organization.id,
          sort_by: "displayName",
          sort_order: "descending"
        )

      assert Enum.map(desc_groups, & &1.name) == ["Support", "Finance", "Engineering"]

      {:ok, page_1} = Accounts.list_groups_scim(organization.id, page: 1, per_page: 2)
      assert length(page_1) == 2
    end

    test "filters groups by displayName", %{organization: organization} do
      {:ok, groups} =
        Accounts.list_groups_scim(organization.id, filter: "displayName eq \"Support\"")

      assert Enum.map(groups, & &1.name) == ["Support"]

      {:ok, count} = Accounts.count_groups_scim(organization.id, filter: "displayName co \"n\"")
      assert count == 2
    end

    test "propagates filter errors for groups", %{organization: organization} do
      assert {:error, _} = Accounts.list_groups_scim(organization.id, filter: "bad filter")
      assert {:error, _} = Accounts.count_groups_scim(organization.id, filter: "bad filter")
    end
  end

  describe "SCIM create/update helpers" do
    setup do
      organization = organization_fixture()
      %{organization: organization}
    end

    test "create_user_scim sets timestamps and random password", %{organization: organization} do
      {:ok, user} =
        Accounts.create_user_scim(scim_user_attrs(%{username: "scim-user"}), organization.id)

      assert user.scim_created_at
      assert user.scim_updated_at
      refute User.valid_password?(user, "")
    end

    test "update_user_scim updates timestamp", %{organization: organization} do
      {:ok, user} = Accounts.create_user_scim(scim_user_attrs(%{}), organization.id)
      original_updated_at = user.scim_updated_at

      {:ok, updated_user} = Accounts.update_user_scim(user, %{first_name: "Updated"})
      assert updated_user.first_name == "Updated"
      assert updated_user.scim_updated_at
      assert DateTime.compare(updated_user.scim_updated_at, original_updated_at) in [:gt, :eq]
    end

    test "create_group_scim sets SCIM timestamps", %{organization: organization} do
      {:ok, group} = Accounts.create_group_scim(%{name: "SCIM Group"}, organization.id)

      assert group.scim_created_at
      assert group.scim_updated_at
      assert group.organization_id == organization.id
    end

    test "update_group_scim refreshes timestamp", %{organization: organization} do
      {:ok, group} = Accounts.create_group_scim(%{name: "SCIM Group"}, organization.id)
      original_updated_at = group.scim_updated_at

      {:ok, updated_group} = Accounts.update_group_scim(group, %{name: "Renamed"})
      assert updated_group.name == "Renamed"
      assert updated_group.scim_updated_at
      assert DateTime.compare(updated_group.scim_updated_at, original_updated_at) in [:gt, :eq]
    end
  end

  defp scim_user_attrs(overrides) do
    email = Map.get(overrides, :email, unique_user_email())

    base = %{
      username: Map.get(overrides, :username, "user-#{System.unique_integer()}"),
      first_name: Map.get(overrides, :first_name, "Test"),
      last_name: Map.get(overrides, :last_name, "User"),
      active: Map.get(overrides, :active, true),
      emails:
        Map.get(overrides, :emails, [
          %{"value" => email, "type" => "work", "primary" => true}
        ])
    }

    Map.merge(base, Map.drop(overrides, [:email]))
  end
end
