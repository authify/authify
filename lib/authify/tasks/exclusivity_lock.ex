defmodule Authify.Tasks.ExclusivityLock do
  @moduledoc """
  Provides mutex-style locking for task exclusivity checks.

  Ensures that only one task with a given exclusivity key can evaluate
  candidates and transition to `:running` at a time. This eliminates the
  TOCTOU race where two identical tasks could both see no duplicates and
  both proceed concurrently.

  The lock is held only for the brief duration of the exclusivity query
  and state transition — not during task execution itself.

  ## How it works

  Each unique key gets a short-lived `GenServer` registered in a `Registry`.
  Callers acquire the lock via a blocking `GenServer.call(:acquire, ...)`,
  execute their function in their own process, then release via a cast.
  The GenServer grants access to one caller at a time by deferring replies
  to queued callers until the current holder releases the lock.

  The server terminates automatically after a period of inactivity.
  """

  use GenServer

  @registry __MODULE__.Registry
  @idle_timeout 30_000

  # --- Public API ---

  @doc """
  Returns the child specs to add to the application supervision tree.
  """
  def child_specs do
    [{Registry, keys: :unique, name: @registry}]
  end

  @doc """
  Executes `fun` while holding an exclusive lock on `key`.

  Only one caller per key can execute at a time. Other callers for the same
  key block until the lock is released. Different keys execute concurrently.
  """
  def with_lock(key, fun) when is_function(fun, 0) do
    pid = start_or_find(key)
    GenServer.call(pid, :acquire, :infinity)

    try do
      fun.()
    after
      GenServer.cast(pid, :release)
    end
  end

  # --- Server Lifecycle ---

  defp start_or_find(key) do
    name = {:via, Registry, {@registry, key}}

    case GenServer.start(__MODULE__, key, name: name) do
      {:ok, pid} -> pid
      {:error, {:already_started, pid}} -> pid
    end
  end

  @impl true
  def init(_key) do
    {:ok, %{holder: nil, queue: :queue.new()}, @idle_timeout}
  end

  @impl true
  def handle_call(:acquire, from, %{holder: nil} = state) do
    # No one holds the lock — grant immediately
    {:reply, :ok, %{state | holder: from}, @idle_timeout}
  end

  def handle_call(:acquire, from, %{holder: _holder, queue: queue} = state) do
    # Lock is held — queue this caller (don't reply yet)
    {:noreply, %{state | queue: :queue.in(from, queue)}, @idle_timeout}
  end

  @impl true
  def handle_cast(:release, %{queue: queue} = state) do
    case :queue.out(queue) do
      {{:value, next_caller}, queue} ->
        # Grant lock to next waiting caller
        GenServer.reply(next_caller, :ok)
        {:noreply, %{state | holder: next_caller, queue: queue}, @idle_timeout}

      {:empty, queue} ->
        # No one waiting — mark as free
        {:noreply, %{state | holder: nil, queue: queue}, @idle_timeout}
    end
  end

  @impl true
  def handle_info(:timeout, state) do
    {:stop, :normal, state}
  end
end
