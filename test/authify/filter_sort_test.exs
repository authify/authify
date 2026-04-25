defmodule Authify.FilterSortTest do
  use Authify.DataCase, async: true

  import Ecto.Query
  import Authify.AccountsFixtures
  import Authify.SAMLFixtures

  alias Authify.FilterSort
  alias Authify.Repo
  alias Authify.SAML.ServiceProvider

  defp sp_fixture(org, overrides \\ []) do
    defaults = [organization: org, entity_id: "https://sp-#{System.unique_integer()}.example.com"]
    service_provider_fixture(Keyword.merge(defaults, overrides))
  end

  describe "apply_multi_text_filter/3" do
    test "returns query unchanged when search_term is nil" do
      org = organization_fixture()
      sp = sp_fixture(org)

      results =
        ServiceProvider
        |> where([s], s.organization_id == ^org.id)
        |> FilterSort.apply_multi_text_filter([:entity_id, :acs_url], nil)
        |> Repo.all()

      assert Enum.any?(results, &(&1.id == sp.id))
    end

    test "returns query unchanged when search_term is empty string" do
      org = organization_fixture()
      sp = sp_fixture(org)

      results =
        ServiceProvider
        |> where([s], s.organization_id == ^org.id)
        |> FilterSort.apply_multi_text_filter([:entity_id, :acs_url], "")
        |> Repo.all()

      assert Enum.any?(results, &(&1.id == sp.id))
    end

    test "matches records where the first field contains the search term" do
      org = organization_fixture()
      match = sp_fixture(org, entity_id: "https://findme.example.com")
      no_match = sp_fixture(org, entity_id: "https://other.example.com")

      results =
        ServiceProvider
        |> where([s], s.organization_id == ^org.id)
        |> FilterSort.apply_multi_text_filter([:entity_id, :acs_url], "findme")
        |> Repo.all()

      ids = Enum.map(results, & &1.id)
      assert match.id in ids
      refute no_match.id in ids
    end

    test "matches records where the second field contains the search term" do
      org = organization_fixture()
      match = sp_fixture(org, acs_url: "https://findme.example.com/acs")
      no_match = sp_fixture(org, acs_url: "https://other.example.com/acs")

      results =
        ServiceProvider
        |> where([s], s.organization_id == ^org.id)
        |> FilterSort.apply_multi_text_filter([:entity_id, :acs_url], "findme")
        |> Repo.all()

      ids = Enum.map(results, & &1.id)
      assert match.id in ids
      refute no_match.id in ids
    end

    test "matches records that satisfy any field (OR semantics)" do
      org = organization_fixture()
      entity_match = sp_fixture(org, entity_id: "https://findme.example.com")
      acs_match = sp_fixture(org, acs_url: "https://findme.example.com/acs")
      no_match = sp_fixture(org)

      results =
        ServiceProvider
        |> where([s], s.organization_id == ^org.id)
        |> FilterSort.apply_multi_text_filter([:entity_id, :acs_url], "findme")
        |> Repo.all()

      ids = Enum.map(results, & &1.id)
      assert entity_match.id in ids
      assert acs_match.id in ids
      refute no_match.id in ids
    end
  end

  describe "apply_sort/5 with default option" do
    test "applies default sort when sort_field is nil" do
      org = organization_fixture()
      first = sp_fixture(org)
      second = sp_fixture(org)

      results =
        ServiceProvider
        |> where([s], s.organization_id == ^org.id)
        |> FilterSort.apply_sort(nil, "asc", [:entity_id], default: [desc: :id])
        |> Repo.all()

      ids = Enum.map(results, & &1.id)
      assert Enum.find_index(ids, &(&1 == second.id)) < Enum.find_index(ids, &(&1 == first.id))
    end

    test "applies default sort when sort_field is not in allowed_fields" do
      org = organization_fixture()
      first = sp_fixture(org)
      second = sp_fixture(org)

      results =
        ServiceProvider
        |> where([s], s.organization_id == ^org.id)
        |> FilterSort.apply_sort(:bad_field, "asc", [:entity_id], default: [desc: :id])
        |> Repo.all()

      ids = Enum.map(results, & &1.id)
      assert Enum.find_index(ids, &(&1 == second.id)) < Enum.find_index(ids, &(&1 == first.id))
    end

    test "ignores default when sort_field is valid" do
      org = organization_fixture()
      sp_a = sp_fixture(org, entity_id: "https://aaa.example.com")
      sp_z = sp_fixture(org, entity_id: "https://zzz.example.com")

      results =
        ServiceProvider
        |> where([s], s.organization_id == ^org.id)
        |> FilterSort.apply_sort(:entity_id, "asc", [:entity_id], default: [desc: :inserted_at])
        |> Repo.all()

      ids = Enum.map(results, & &1.id)
      assert Enum.find_index(ids, &(&1 == sp_a.id)) < Enum.find_index(ids, &(&1 == sp_z.id))
    end

    test "returns unchanged query when field is invalid and no default is given (backward compat)" do
      org = organization_fixture()
      sp_fixture(org)

      base =
        ServiceProvider
        |> where([s], s.organization_id == ^org.id)

      result = FilterSort.apply_sort(base, nil, "asc", [:entity_id])
      assert result == base
    end
  end
end
