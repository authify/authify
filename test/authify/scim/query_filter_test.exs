defmodule Authify.SCIM.QueryFilterTest do
  use Authify.DataCase, async: true

  import Ecto.Query
  import Authify.AccountsFixtures
  alias Authify.Accounts.User

  alias Authify.Accounts
  alias Authify.Accounts.User
  alias Authify.SCIM.QueryFilter

  describe "apply_filter/3" do
    setup do
      %{query: from(u in User)}
    end

    test "returns query unchanged when AST is nil", %{query: query} do
      assert {:ok, ^query} = QueryFilter.apply_filter(query, nil, :user)
    end

    test "applies equality filter to userName", %{query: query} do
      {:ok, filtered_query} = QueryFilter.apply_filter(query, {:eq, "userName", "jsmith"}, :user)
      {sql, params} = Repo.to_sql(:all, filtered_query)

      assert sql =~ "`username` = ?"
      assert params == ["jsmith"]
    end

    test "applies contains filter and boolean comparison", %{query: query} do
      ast = {:and, {:eq, "active", "true"}, {:co, "userName", "ops"}}
      {:ok, filtered_query} = QueryFilter.apply_filter(query, ast, :user)
      {sql, params} = Repo.to_sql(:all, filtered_query)

      assert sql =~ "`active`"
      assert sql =~ "LIKE"
      assert params == [true, "%ops%"]
    end

    test "filters by email using EXISTS subquery" do
      organization = organization_fixture()

      {:ok, matching_user} =
        Accounts.create_user_scim(scim_user_attrs(email: "match@example.com"), organization.id)

      {:ok, _other_user} =
        Accounts.create_user_scim(scim_user_attrs(email: "other@example.com"), organization.id)

      base_query =
        from(u in User,
          where: u.organization_id == ^organization.id
        )

      {:ok, filtered_query} =
        QueryFilter.apply_filter(base_query, {:eq, "emails.value", "match@example.com"}, :user)

      result_ids = Repo.all(filtered_query) |> Enum.map(& &1.id)
      assert result_ids == [matching_user.id]
    end

    test "rejects unknown attributes" do
      {:error, :unknown_attribute} =
        QueryFilter.apply_filter(from(u in User), {:eq, "unknown", "value"}, :user)
    end

    test "supports group filters" do
      ast = {:pr, "displayName"}

      {:ok, filtered_query} =
        QueryFilter.apply_filter(from(u in Authify.Accounts.Group), ast, :group)

      {sql, _params} = Repo.to_sql(:all, filtered_query)

      assert sql =~ "`name`"
    end
  end

  defp scim_user_attrs(overrides) do
    overrides = Map.new(overrides)
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

    overrides
    |> Map.drop([:email])
    |> then(&Map.merge(base, &1))
  end
end
