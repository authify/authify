defmodule Authify.SCIMClient.RetryScheduler do
  @moduledoc """
  Periodically retries failed SCIM sync operations.
  Runs every 5 minutes, retries up to 5 times with exponential backoff.
  """
  use GenServer

  require Logger

  alias Authify.SCIMClient.{Client, Provisioner}

  @retry_interval :timer.minutes(5)

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    schedule_retry_check()
    {:ok, %{}}
  end

  @impl true
  def handle_info(:check_retries, state) do
    retry_failed_syncs()
    schedule_retry_check()
    {:noreply, state}
  end

  # Private functions

  defp retry_failed_syncs do
    logs = Client.get_retriable_sync_logs()

    unless Enum.empty?(logs) do
      Logger.info("Retrying #{length(logs)} failed SCIM sync operations")
    end

    Enum.each(logs, fn log ->
      Task.Supervisor.start_child(
        Authify.TaskSupervisor,
        fn -> Provisioner.retry_sync(log) end
      )
    end)
  end

  defp schedule_retry_check do
    Process.send_after(self(), :check_retries, @retry_interval)
  end
end
