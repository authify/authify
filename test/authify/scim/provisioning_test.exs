defmodule Authify.SCIM.ProvisioningTest do
  use Authify.DataCase, async: true

  import Authify.AccountsFixtures

  alias Authify.Accounts.{User, UserEmail}
  alias Authify.Groups
  alias Authify.Repo
  alias Authify.SCIM.Provisioning

  describe "list_users_scim/2 and count_users_scim/2" do
    setup do
      organization = organization_fixture()

      {:ok, _} =
        Provisioning.create_user_scim(
          scim_user_attrs(%{username: "alpha", active: true}),
          organization.id
        )

      {:ok, _} =
        Provisioning.create_user_scim(
          scim_user_attrs(%{username: "beta", active: false}),
          organization.id
        )

      {:ok, _} =
        Provisioning.create_user_scim(
          scim_user_attrs(%{username: "gamma", active: true}),
          organization.id
        )

      %{organization: organization}
    end

    test "paginates results and enforces max page size", %{organization: organization} do
      {:ok, users} = Provisioning.list_users_scim(organization.id, page: 1, per_page: 2)
      assert length(users) == 2

      {:ok, users_page_2} = Provisioning.list_users_scim(organization.id, page: 2, per_page: 2)
      assert length(users_page_2) == 1

      {:ok, users_max} = Provisioning.list_users_scim(organization.id, per_page: 500)
      assert length(users_max) <= 100
    end

    test "sorts by userName ascending and descending", %{organization: organization} do
      {:ok, asc_users} =
        Provisioning.list_users_scim(organization.id,
          sort_by: "userName",
          sort_order: "ascending"
        )

      assert Enum.map(asc_users, & &1.username) == Enum.sort(Enum.map(asc_users, & &1.username))

      {:ok, desc_users} =
        Provisioning.list_users_scim(organization.id,
          sort_by: "userName",
          sort_order: "descending"
        )

      assert Enum.map(desc_users, & &1.username) ==
               Enum.sort(Enum.map(desc_users, & &1.username), :desc)
    end

    test "filters using SCIM filter string", %{organization: organization} do
      {:ok, users} =
        Provisioning.list_users_scim(organization.id,
          filter: "userName sw \"a\"",
          sort_by: "userName"
        )

      assert length(users) == 1
      assert hd(users).username == "alpha"

      {:ok, count} = Provisioning.count_users_scim(organization.id, filter: "active eq true")
      assert count == 2
    end

    test "propagates filter errors" do
      organization = organization_fixture()

      assert {:error, _} = Provisioning.list_users_scim(organization.id, filter: "invalid filter")

      assert {:error, _} =
               Provisioning.count_users_scim(organization.id, filter: "invalid filter")
    end
  end

  describe "list_groups_scim/2 and count_groups_scim/2" do
    setup do
      organization = organization_fixture()

      {:ok, group_a} = Provisioning.create_group_scim(%{name: "Engineering"}, organization.id)
      {:ok, group_b} = Provisioning.create_group_scim(%{name: "Support"}, organization.id)
      {:ok, group_c} = Provisioning.create_group_scim(%{name: "Finance"}, organization.id)

      %{organization: organization, group_a: group_a, group_b: group_b, group_c: group_c}
    end

    test "paginates and sorts groups", %{organization: organization} do
      {:ok, groups} = Provisioning.list_groups_scim(organization.id, sort_by: "displayName")
      assert Enum.map(groups, & &1.name) == ["Engineering", "Finance", "Support"]

      {:ok, desc_groups} =
        Provisioning.list_groups_scim(organization.id,
          sort_by: "displayName",
          sort_order: "descending"
        )

      assert Enum.map(desc_groups, & &1.name) == ["Support", "Finance", "Engineering"]

      {:ok, page_1} = Provisioning.list_groups_scim(organization.id, page: 1, per_page: 2)
      assert length(page_1) == 2
    end

    test "filters groups by displayName", %{organization: organization} do
      {:ok, groups} =
        Provisioning.list_groups_scim(organization.id, filter: "displayName eq \"Support\"")

      assert Enum.map(groups, & &1.name) == ["Support"]

      {:ok, count} =
        Provisioning.count_groups_scim(organization.id, filter: "displayName co \"n\"")

      assert count == 2
    end

    test "propagates filter errors for groups", %{organization: organization} do
      assert {:error, _} = Provisioning.list_groups_scim(organization.id, filter: "bad filter")
      assert {:error, _} = Provisioning.count_groups_scim(organization.id, filter: "bad filter")
    end
  end

  describe "SCIM create/update helpers" do
    setup do
      organization = organization_fixture()
      %{organization: organization}
    end

    test "create_user_scim sets timestamps and random password", %{organization: organization} do
      {:ok, user} =
        Provisioning.create_user_scim(scim_user_attrs(%{username: "scim-user"}), organization.id)

      assert user.scim_created_at
      assert user.scim_updated_at
      refute User.valid_password?(user, "")
    end

    test "create_user_scim generates password satisfying relaxed org policy", %{
      organization: organization
    } do
      Authify.Configurations.get_or_create_configuration(
        "Organization",
        organization.id,
        "organization"
      )

      for setting <- [
            :password_require_uppercase,
            :password_require_lowercase,
            :password_require_digit,
            :password_require_special
          ] do
        {:ok, _} =
          Authify.Configurations.set_setting("Organization", organization.id, setting, false)
      end

      # Under a relaxed policy, provisioning a user must still succeed and the
      # generated password must be accepted by the organization's policy.
      assert {:ok, user} =
               Provisioning.create_user_scim(
                 scim_user_attrs(%{username: "scim-relaxed"}),
                 organization.id
               )

      assert user.scim_created_at
    end

    test "create_user_scim generates a username when userName is an email address", %{
      organization: organization
    } do
      # SCIM clients often send an email-shaped userName, which is mapped to the
      # email addresses only — no username — so one must be generated.
      n = rem(System.unique_integer([:positive]), 100_000)

      attrs =
        AuthifyWeb.SCIM.Mappers.map_user_attrs(%{
          "userName" => "scimalice#{n}@example.com",
          "name" => %{"givenName" => "Scim", "familyName" => "Alice"},
          "active" => true
        })

      assert {:ok, user} = Provisioning.create_user_scim(attrs, organization.id)

      assert user.username == "scimalice#{n}"
      refute String.contains?(user.username, "@")
    end

    test "create_user_scim preserves a supplied username", %{organization: organization} do
      {:ok, user} =
        Provisioning.create_user_scim(
          scim_user_attrs(%{username: "Supplied-Username-1"}),
          organization.id
        )

      assert user.username == "Supplied-Username-1"
    end

    test "create_user_scim rejects a duplicate supplied username", %{organization: organization} do
      {:ok, _user} =
        Provisioning.create_user_scim(
          scim_user_attrs(%{username: "scim-dupe-one"}),
          organization.id
        )

      assert {:error, %Ecto.Changeset{} = changeset} =
               Provisioning.create_user_scim(
                 scim_user_attrs(%{username: "scim-dupe-one", email: "other@example.com"}),
                 organization.id
               )

      assert %{username: [_ | _]} = errors_on(changeset)
    end

    test "update_user_scim updates timestamp", %{organization: organization} do
      {:ok, user} = Provisioning.create_user_scim(scim_user_attrs(%{}), organization.id)
      original_updated_at = user.scim_updated_at

      {:ok, updated_user} = Provisioning.update_user_scim(user, %{first_name: "Updated"})
      assert updated_user.first_name == "Updated"
      assert updated_user.scim_updated_at
      assert DateTime.compare(updated_user.scim_updated_at, original_updated_at) in [:gt, :eq]
    end

    test "create_group_scim sets SCIM timestamps", %{organization: organization} do
      {:ok, group} = Provisioning.create_group_scim(%{name: "SCIM Group"}, organization.id)

      assert group.scim_created_at
      assert group.scim_updated_at
      assert group.organization_id == organization.id
    end

    test "update_group_scim refreshes timestamp", %{organization: organization} do
      {:ok, group} = Provisioning.create_group_scim(%{name: "SCIM Group"}, organization.id)
      original_updated_at = group.scim_updated_at

      {:ok, updated_group} = Provisioning.update_group_scim(group, %{name: "Renamed"})
      assert updated_group.name == "Renamed"
      assert updated_group.scim_updated_at
      assert DateTime.compare(updated_group.scim_updated_at, original_updated_at) in [:gt, :eq]
    end
  end

  describe "get_group_by_external_id/2" do
    setup do
      organization = organization_fixture()
      %{organization: organization}
    end

    test "finds group by external_id", %{organization: org} do
      {:ok, group} =
        Groups.create_group(%{
          "name" => "ExtLookup",
          "organization_id" => org.id,
          "external_id" => "lookup-ext-id"
        })

      found = Provisioning.get_group_by_external_id("lookup-ext-id", org.id)
      assert found.id == group.id
    end

    test "returns nil when not found", %{organization: org} do
      assert Provisioning.get_group_by_external_id("nonexistent", org.id) == nil
    end

    test "returns nil for nil arguments" do
      assert Provisioning.get_group_by_external_id(nil, nil) == nil
    end
  end

  describe "update_user_emails_scim/2" do
    setup do
      organization = organization_fixture()

      {:ok, user} =
        Provisioning.create_user_scim(
          scim_user_attrs(%{
            emails: [
              %{"value" => "work@example.com", "type" => "work", "primary" => true},
              %{"value" => "home@example.com", "type" => "home"}
            ]
          }),
          organization.id
        )

      %{user: Repo.preload(user, :emails, force: true)}
    end

    test "replaces the collection, removing extras and forcing a single primary", %{user: user} do
      assert {:ok, updated} =
               Provisioning.update_user_emails_scim(user, [
                 %{"value" => "new-work@example.com", "type" => "work"},
                 %{"value" => "home@example.com", "type" => "home", "primary" => true}
               ])

      values = updated.emails |> Enum.map(& &1.value) |> Enum.sort()
      assert values == ["home@example.com", "new-work@example.com"]
      assert Enum.count(updated.emails, & &1.primary) == 1
      assert Enum.find(updated.emails, & &1.primary).value == "home@example.com"
      assert updated.scim_updated_at
    end

    test "preserves verification state for unchanged values", %{user: user} do
      work_email = Enum.find(user.emails, &(&1.value == "work@example.com"))
      {:ok, _} = work_email |> UserEmail.verify_changeset() |> Repo.update()

      assert {:ok, updated} =
               Provisioning.update_user_emails_scim(user, [
                 %{"value" => "work@example.com", "type" => "work", "primary" => true},
                 %{"value" => "extra@example.com", "type" => "home"}
               ])

      assert Enum.find(updated.emails, &(&1.value == "work@example.com")).verified_at
    end

    test "returns an error when the desired collection is empty", %{user: user} do
      assert {:error, reason} = Provisioning.update_user_emails_scim(user, [])
      assert reason =~ "at least one email"
    end

    test "returns an error when an entry has no value", %{user: user} do
      assert {:error, reason} =
               Provisioning.update_user_emails_scim(user, [%{"type" => "work"}])

      assert reason =~ "must include a value"
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
