defmodule Authify.Accounts.UsernameBackfillTest do
  @moduledoc """
  Tests for the username backfill used by the `backfill_user_usernames`
  data migration: users with `username IS NULL` receive sanitized,
  per-organization-unique usernames.

  The `users.username` column is NOT NULL once the migration has run, so tests
  create rows with placeholder usernames and target them through an overridden
  queryable — the same row logic the migration runs against real NULL rows.
  """

  use Authify.DataCase, async: true

  alias Authify.Accounts
  alias Authify.Accounts.User
  alias Authify.Repo
  import Ecto.Query

  defp missing_query(user_ids) do
    from(u in User,
      left_join: e in Authify.Accounts.UserEmail,
      on: e.user_id == u.id and e.primary == true,
      where: u.id in ^user_ids,
      select: %{id: u.id, organization_id: u.organization_id, email: e.value},
      order_by: u.id
    )
  end

  defp create_backfill_target(organization_id, email, marker) do
    {:ok, user} =
      Repo.insert(%User{
        organization_id: organization_id,
        hashed_password: "placeholder-hash",
        first_name: marker,
        last_name: "BackfillTarget",
        # Placeholder to satisfy the NOT NULL constraint; the backfill rewrites it
        username: "backfill-marker-#{marker}"
      })

    if email do
      Repo.insert(%Authify.Accounts.UserEmail{
        user_id: user.id,
        value: email,
        type: "work",
        primary: true
      })
    end

    user.id
  end

  test "assigns usernames seeded from the primary email, uniquely per organization" do
    {:ok, org} = Accounts.create_organization(%{name: "Backfill Org", slug: "backfill-org-1"})

    id_1 = create_backfill_target(org.id, "alice@one.example", "alice-one")
    id_2 = create_backfill_target(org.id, "alice@two.example", "alice-two")

    assert {:ok, 2} = Accounts.backfill_missing_usernames(missing_query([id_1, id_2]))

    usernames =
      from(u in User,
        where: u.id in ^[id_1, id_2],
        select: u.username
      )
      |> Repo.all()

    assert length(Enum.uniq(usernames)) == 2
    assert Enum.all?(usernames, &is_binary/1)

    # Both users had the same email local part, so exactly one keeps the bare
    # seed and the other gets a unique suffix — neither may be email-shaped.
    assert Enum.count(usernames, &(&1 == "alice")) == 1
    assert Enum.any?(usernames, &String.starts_with?(&1, "alice"))
    assert Enum.all?(usernames, fn username -> not String.contains?(username, "@") end)
  end

  test "generates usernames with the default seed when no email is available" do
    {:ok, org} = Accounts.create_organization(%{name: "Seedless Org", slug: "seedless-org-1"})

    user_id = create_backfill_target(org.id, nil, "seedless")

    assert {:ok, 1} = Accounts.backfill_missing_usernames(missing_query([user_id]))

    assert Repo.one(from(u in User, where: u.id == ^user_id, select: u.username)) == "user"
  end

  test "allows the same username across different organizations" do
    {:ok, org_a} = Accounts.create_organization(%{name: "Org A", slug: "org-a-backfill"})
    {:ok, org_b} = Accounts.create_organization(%{name: "Org B", slug: "org-b-backfill"})

    id_a = create_backfill_target(org_a.id, "carol@alpha.example", "org-a")
    id_b = create_backfill_target(org_b.id, "carol@beta.example", "org-b")

    assert {:ok, 2} = Accounts.backfill_missing_usernames(missing_query([id_a, id_b]))

    assert Repo.one(from(u in User, where: u.id == ^id_a, select: u.username)) == "carol"
    assert Repo.one(from(u in User, where: u.id == ^id_b, select: u.username)) == "carol"
  end

  test "leaves users that already have usernames untouched by default" do
    {:ok, user} =
      Accounts.create_user(%{
        "emails" => [%{"value" => "kept@example.com", "type" => "work", "primary" => true}],
        "first_name" => "Kept",
        "last_name" => "User",
        "username" => "existing-kept-name",
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      })

    assert {:ok, 0} = Accounts.backfill_missing_usernames()

    assert Repo.one(from(u in User, where: u.id == ^user.id, select: u.username)) ==
             "existing-kept-name"
  end
end
