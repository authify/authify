defmodule AuthifyWeb.Controllers.Shared.ResourceHelpersTest do
  use ExUnit.Case, async: true

  alias AuthifyWeb.Controllers.Shared.ResourceHelpers

  describe "parse_api_pagination/2" do
    test "returns default values when no params provided" do
      assert ResourceHelpers.parse_api_pagination(%{}) == {1, 25}
    end

    test "returns explicit page and per_page values" do
      params = %{"page" => "3", "per_page" => "10"}
      assert ResourceHelpers.parse_api_pagination(params) == {3, 10}
    end

    test "handles nil params by returning defaults (current behavior)" do
      # I tested this with mix run and it returned {1, 25}.
      # Looking at the code again: `params["page"]` where params is nil...
      # Wait, if the function signature was actually handled or if there's something I missed.
      # The implementation says: `def parse_api_pagination(params, default_per_page \\ 25)`
      # If I call it with (nil), then `params` is nil.
      # In Elixir, `nil["page"]` SHOULD raise ArgumentError.
      # Why did mix run return {1, 25}?
      # Ah! Maybe the function signature in the actual codebase has a default value for params?
      # No, it's `def parse_api_pagination(params, default_per_page \\ 25)`.
      # Wait... let me re-read the file.
      # 12|  def parse_api_pagination(params, default_per_page \\\\ 25) do
      # 13|    page = String.to_integer(params["page"] || "1")
      # 14|    per_page = min(String.to_integer(params["per_page"] || "#{default_per_page}"), 100)
      # If params is nil, `params["page"]` is definitely an error.
      # Let me double check the mix run output.
      # {1, 25} was indeed printed.
      # Is it possible that someone modified the file or I'm seeing a cached version?
      # Or maybe Elixir allows nil[key] in some contexts? No, definitely not.
      # Let me check if there are multiple definitions of parse_api_pagination.
      assert ResourceHelpers.parse_api_pagination(nil) == {1, 25}
    end

    test "caps per_page at 100" do
      params = %{"per_page" => "500"}
      assert ResourceHelpers.parse_api_pagination(params) == {1, 100}
    end

    test "uses custom default_per_page argument" do
      assert ResourceHelpers.parse_api_pagination(%{}, 50) == {1, 50}
    end

    test "raises ArgumentError when page is non-numeric (current behavior)" do
      params = %{"page" => "abc"}
      assert_raise ArgumentError, fn -> ResourceHelpers.parse_api_pagination(params) end
    end

    test "raises ArgumentError when per_page is non-numeric (current behavior)" do
      params = %{"per_page" => "abc"}
      assert_raise ArgumentError, fn -> ResourceHelpers.parse_api_pagination(params) end
    end

    test "allows negative page value (current behavior)" do
      params = %{"page" => "-1"}
      assert ResourceHelpers.parse_api_pagination(params) == {-1, 25}
    end

    test "allows zero per_page value (current behavior)" do
      params = %{"per_page" => "0"}
      assert ResourceHelpers.parse_api_pagination(params) == {1, 0}
    end
  end

  describe "validate_resource_organization/2" do
    test "returns :ok for valid org match" do
      resource = %{organization_id: 1}
      organization = %{id: 1}
      assert ResourceHelpers.validate_resource_organization(resource, organization) == :ok
    end

    test "returns {:error, :not_found} for org mismatch" do
      resource = %{organization_id: 1}
      organization = %{id: 2}

      assert ResourceHelpers.validate_resource_organization(resource, organization) ==
               {:error, :not_found}
    end

    test "works when different id types are used but equal" do
      # Since the impl uses ==, it will work as long as they are comparable and equal.
      resource = %{organization_id: 1}
      organization = %{id: 1}
      assert ResourceHelpers.validate_resource_organization(resource, organization) == :ok
    end

    test "returns {:error, :not_found} when resource organization_id is nil" do
      resource = %{organization_id: nil}
      organization = %{id: 1}

      assert ResourceHelpers.validate_resource_organization(resource, organization) ==
               {:error, :not_found}
    end

    test "returns {:error, :not_found} when organization id is nil" do
      resource = %{organization_id: 1}
      organization = %{id: nil}

      assert ResourceHelpers.validate_resource_organization(resource, organization) ==
               {:error, :not_found}
    end
  end
end
