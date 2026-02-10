defmodule Authify.Tasks.Task do
  @moduledoc """
  Schema for tasks in the task engine. Defines task fields, state categories,
  validations, and params key sorting for consistent idempotency comparison.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  # State categories
  @active_states [:scheduled, :pending, :running, :waiting, :retrying]
  @transitioning_states [
    :completing,
    :failing,
    :expiring,
    :cancelling,
    :timing_out,
    :skipping
  ]
  @terminal_states [:completed, :failed, :expired, :timed_out, :cancelled, :skipped]
  @all_states @active_states ++ @transitioning_states ++ @terminal_states

  # Expose state lists for use by other modules
  def active_states, do: @active_states
  def transitioning_states, do: @transitioning_states
  def terminal_states, do: @terminal_states
  def all_states, do: @all_states
  def non_terminal_states, do: @active_states ++ @transitioning_states

  schema "tasks" do
    field :type, :string
    field :action, :string
    field :params, :map, default: %{}
    field :status, Ecto.Enum, values: @all_states, default: :pending
    field :priority, :integer, default: 0
    field :max_retries, :integer, default: 3
    field :retry_count, :integer, default: 0
    field :timeout_seconds, :integer
    field :scheduled_at, :utc_datetime
    field :started_at, :utc_datetime
    field :completed_at, :utc_datetime
    field :failed_at, :utc_datetime
    field :expires_at, :utc_datetime
    field :results, :map, default: %{}
    field :errors, :map, default: %{}
    field :correlation_id, :string
    field :metadata, :map, default: %{}

    belongs_to :organization, Authify.Accounts.Organization
    belongs_to :parent, Authify.Tasks.Task
    has_many :children, Authify.Tasks.Task, foreign_key: :parent_id
    has_many :logs, Authify.Tasks.TaskLog

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(task, attrs) do
    task
    |> cast(attrs, [
      :type,
      :action,
      :params,
      :status,
      :priority,
      :max_retries,
      :retry_count,
      :timeout_seconds,
      :scheduled_at,
      :started_at,
      :completed_at,
      :failed_at,
      :expires_at,
      :results,
      :errors,
      :correlation_id,
      :metadata,
      :organization_id,
      :parent_id
    ])
    |> validate_required([:type, :action, :status])
    |> validate_inclusion(:status, @all_states)
    |> validate_number(:priority, greater_than_or_equal_to: 0)
    |> validate_number(:max_retries, greater_than_or_equal_to: 0)
    |> validate_number(:retry_count, greater_than_or_equal_to: 0)
    |> validate_number(:timeout_seconds, greater_than: 0)
    |> sort_params_keys()
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:parent_id)
  end

  # Sort map keys alphabetically for consistent comparison
  defp sort_params_keys(%Ecto.Changeset{valid?: true} = changeset) do
    case get_change(changeset, :params) do
      nil -> changeset
      params when is_map(params) -> put_change(changeset, :params, sort_map_keys(params))
    end
  end

  defp sort_params_keys(changeset), do: changeset

  defp sort_map_keys(map) when is_map(map) do
    map
    |> Enum.sort_by(fn {key, _value} -> to_string(key) end)
    |> Enum.map(fn {key, value} -> {key, sort_map_keys(value)} end)
    |> Enum.into(%{})
  end

  defp sort_map_keys(list) when is_list(list) do
    Enum.map(list, &sort_map_keys/1)
  end

  defp sort_map_keys(value), do: value
end
