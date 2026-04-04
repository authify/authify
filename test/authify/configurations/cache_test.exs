defmodule Authify.Configurations.CacheTest do
  # async: false — tests directly manipulate shared ETS state
  # in the global configuration cache GenServer.
  use ExUnit.Case, async: false

  alias Authify.Configurations.Cache

  setup do
    Cache.clear()
    on_exit(fn -> Cache.clear() end)
    :ok
  end

  describe "get/3 and put/4" do
    test "returns :miss when key not present" do
      assert :miss = Cache.get("Organization", 999_999, :nonexistent)
    end

    test "returns {:ok, value} after put" do
      Cache.put("Organization", 1, :test_key, "hello")
      assert {:ok, "hello"} = Cache.get("Organization", 1, :test_key)
    end

    test "normalises setting_name atom and string to same key" do
      Cache.put("Organization", 1, :atom_key, "value")
      assert {:ok, "value"} = Cache.get("Organization", 1, "atom_key")
    end
  end

  describe "invalidate/3" do
    test "removes a specific cached entry without affecting others" do
      Cache.put("Organization", 1, :key1, "value1")
      Cache.put("Organization", 1, :key2, "value2")
      Cache.invalidate("Organization", 1, :key1)
      assert :miss = Cache.get("Organization", 1, :key1)
      assert {:ok, "value2"} = Cache.get("Organization", 1, :key2)
    end
  end

  describe "invalidate_all/2" do
    test "removes all entries for an entity without affecting others" do
      Cache.put("Organization", 1, :key1, "value1")
      Cache.put("Organization", 1, :key2, "value2")
      Cache.put("Organization", 2, :key1, "other")
      Cache.invalidate_all("Organization", 1)
      assert :miss = Cache.get("Organization", 1, :key1)
      assert :miss = Cache.get("Organization", 1, :key2)
      assert {:ok, "other"} = Cache.get("Organization", 2, :key1)
    end
  end

  describe "clear/0" do
    test "removes all entries" do
      Cache.put("Organization", 1, :key1, "v1")
      Cache.put("Organization", 2, :key2, "v2")
      Cache.clear()
      assert :miss = Cache.get("Organization", 1, :key1)
      assert :miss = Cache.get("Organization", 2, :key2)
    end
  end

  describe "bypass_for_test/0" do
    test "makes get/3 always return :miss" do
      Cache.put("Organization", 1, :bypass_key, "value")
      assert {:ok, "value"} = Cache.get("Organization", 1, :bypass_key)
      Cache.bypass_for_test()
      assert :miss = Cache.get("Organization", 1, :bypass_key)
    end

    test "makes put/4 a no-op" do
      Cache.bypass_for_test()
      Cache.put("Organization", 1, :noop_key, "value")
      assert :miss = Cache.get("Organization", 1, :noop_key)
    end

    test "bypass is process-local and does not affect other processes" do
      Cache.put("Organization", 1, :shared_key, "shared_value")
      Cache.bypass_for_test()
      assert :miss = Cache.get("Organization", 1, :shared_key)

      task = Task.async(fn -> Cache.get("Organization", 1, :shared_key) end)
      assert {:ok, "shared_value"} = Task.await(task)
    end
  end
end
