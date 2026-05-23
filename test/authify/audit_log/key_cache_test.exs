defmodule Authify.AuditLog.KeyCacheTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Authify.AuditLog.KeyCache

  setup do
    :ok
  end

  test "get/1 returns :miss when org not in cache" do
    assert KeyCache.get(999_999) == :miss
  end

  test "put/3 and get/1 round-trip" do
    org_id = System.unique_integer([:positive])
    fake_key = :crypto.generate_key(:rsa, {2048, 65_537}) |> elem(0)

    :ok = KeyCache.put(org_id, fake_key, 42)
    {:ok, entry} = KeyCache.get(org_id)

    assert entry.cert_id == 42
    assert entry.private_key == fake_key
  end

  test "invalidate/1 removes entry from cache" do
    org_id = System.unique_integer([:positive])
    fake_key = :crypto.generate_key(:rsa, {2048, 65_537}) |> elem(0)

    :ok = KeyCache.put(org_id, fake_key, 99)
    :ok = KeyCache.invalidate(org_id)

    assert KeyCache.get(org_id) == :miss
  end
end
