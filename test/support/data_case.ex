defmodule Authify.DataCase do
  @moduledoc """
  This module defines the setup for tests requiring
  access to the application's data layer.

  You may define functions here to be used as helpers in
  your tests.

  Finally, if the test case interacts with the database,
  we enable the SQL sandbox, so changes done to the database
  are reverted at the end of every test. If you are using
  PostgreSQL, you can even run database tests asynchronously
  by setting `use Authify.DataCase, async: true`, although
  this option is not recommended for other databases.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      alias Authify.Repo

      import Ecto
      import Ecto.Changeset
      import Ecto.Query
      import Authify.DataCase
    end
  end

  # Tests that MUST use async: false:
  #
  # - Task engine tests (test/authify/tasks/) — shared TaskExecutor GenServer state
  #   and telemetry hooks that register globally.
  # - Scheduled worker tests (test/authify/tasks/workers/scheduled/) — Oban queue state.
  # - Rate limiter tests (test/authify_web/plugs/rate_limiter_test.exs) — Hammer buckets
  #   are global; these tests deliberately test global lockout behavior.
  # - Maintenance controller tests — uses Oban.Testing with manual mode.
  # - LiveView tests (test/authify_web/live/) — Phoenix LiveView process management.
  setup tags do
    Authify.DataCase.setup_sandbox(tags)

    if tags[:async] do
      # Bypass the ETS config cache for this process so async tests always
      # read from the sandbox DB and never share cache state with concurrent tests.
      Authify.Configurations.Cache.bypass_for_test()
    else
      Authify.Configurations.Cache.clear()

      on_exit(fn ->
        Authify.Configurations.Cache.clear()
      end)
    end

    :ok
  end

  @doc """
  Sets up the sandbox based on the test tags.
  """
  def setup_sandbox(tags) do
    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(Authify.Repo, shared: not tags[:async])
    on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
  end

  @doc """
  A helper that transforms changeset errors into a map of messages.

      assert {:error, changeset} = Accounts.create_user(%{password: "short"})
      assert "password is too short" in errors_on(changeset).password
      assert %{password: ["password is too short"]} = errors_on(changeset)

  """
  def errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
