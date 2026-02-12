defmodule Authify.Tasks.TaskLog do
  @moduledoc """
  Schema for task execution logs, stored separately from the tasks table
  to keep it lean. Logs are only loaded when needed for troubleshooting.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, Uniq.UUID, version: 7, autogenerate: true}
  @foreign_key_type Uniq.UUID
  @derive {Jason.Encoder, except: [:__meta__, :__struct__, :task]}

  schema "task_logs" do
    field :log_data, :string

    belongs_to :task, Authify.Tasks.Task

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(task_log, attrs) do
    task_log
    |> cast(attrs, [:log_data, :task_id])
    |> validate_required([:log_data, :task_id])
    |> foreign_key_constraint(:task_id)
  end
end
