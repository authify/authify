defmodule Authify.AuditLog.KeyCache do
  @moduledoc """
  ETS-backed cache for decoded audit signing private keys, keyed by organization ID.

  Avoids a DB round-trip + key decryption on every audit event write for orgs
  with sign_audit_logs enabled. Entries are invalidated when a new audit_signing
  certificate is generated for an org.
  """

  use GenServer

  @table :audit_signing_key_cache

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Returns `{:ok, %{private_key: key, cert_id: id}}` or `:miss`."
  def get(org_id) do
    case :ets.lookup(@table, org_id) do
      [{^org_id, entry}] -> {:ok, entry}
      [] -> :miss
    end
  end

  @doc "Stores a decoded private key and its certificate ID for an org."
  def put(org_id, private_key, cert_id) do
    :ets.insert(@table, {org_id, %{private_key: private_key, cert_id: cert_id}})
    :ok
  end

  @doc "Removes the cached key for an org (call when a new audit_signing cert is created)."
  def invalidate(org_id) do
    :ets.delete(@table, org_id)
    :ok
  end

  @impl true
  def init(_opts) do
    :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    {:ok, %{}}
  end
end
