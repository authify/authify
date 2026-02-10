defmodule Authify.Tasks.StateMachine do
  @moduledoc """
  Validates and enforces task state transitions. Defines the valid transition
  graph and provides functions to check and perform transitions safely.
  """

  alias Authify.Tasks.Task

  # Valid state transitions: {from_state => [allowed_to_states]}
  @transitions %{
    # Active states
    scheduled: [:pending, :running, :cancelling],
    pending: [:running, :skipping, :cancelling],
    running: [:completing, :failing, :retrying, :waiting, :timing_out],
    retrying: [:running, :failing, :cancelling],
    waiting: [:running, :expiring, :cancelling],

    # Transitioning states → corresponding terminal states
    completing: [:completed],
    failing: [:failed],
    expiring: [:expired],
    cancelling: [:cancelled],
    timing_out: [:timed_out],
    skipping: [:skipped]
  }

  @doc """
  Returns the map of all valid state transitions.
  """
  def transitions, do: @transitions

  @doc """
  Returns the list of valid target states from the given state.
  Returns an empty list for terminal states (no transitions allowed).
  """
  def valid_transitions(state) when is_atom(state) do
    Map.get(@transitions, state, [])
  end

  @doc """
  Checks if a transition from `from_state` to `to_state` is valid.
  """
  def valid_transition?(from_state, to_state) do
    to_state in valid_transitions(from_state)
  end

  @doc """
  Attempts to transition a task to a new state. Returns {:ok, changeset}
  if the transition is valid, or {:error, reason} if not.
  """
  def transition(%Task{status: from_state} = task, to_state) do
    if valid_transition?(from_state, to_state) do
      attrs = transition_attrs(to_state)
      {:ok, Task.changeset(task, attrs)}
    else
      {:error, {:invalid_transition, from_state, to_state}}
    end
  end

  # Build the attributes map for a state transition, including timestamp updates
  defp transition_attrs(to_state) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    base = %{status: to_state}

    case to_state do
      :running -> Map.put(base, :started_at, now)
      :completed -> Map.put(base, :completed_at, now)
      :failed -> Map.put(base, :failed_at, now)
      _ -> base
    end
  end
end
