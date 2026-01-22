defmodule Authify.SCIMClient.SyncLog do
  @moduledoc """
  Schema for SCIM provisioning sync logs. Tracks all provisioning attempts,
  their status, and retry information.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias Authify.SCIMClient.ScimClient

  @derive {Jason.Encoder,
           except: [
             :scim_client,
             :__meta__
           ]}

  schema "scim_sync_logs" do
    field :resource_type, :string
    field :resource_id, :integer
    field :operation, :string
    field :status, :string
    field :http_status, :integer
    field :request_body, :string
    field :response_body, :string
    field :error_message, :string
    field :retry_count, :integer, default: 0
    field :next_retry_at, :utc_datetime

    belongs_to :scim_client, ScimClient

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(sync_log, attrs) do
    sync_log
    |> cast(attrs, [
      :scim_client_id,
      :resource_type,
      :resource_id,
      :operation,
      :status,
      :http_status,
      :request_body,
      :response_body,
      :error_message,
      :retry_count,
      :next_retry_at
    ])
    |> validate_required([:scim_client_id, :resource_type, :resource_id, :operation, :status])
    |> validate_inclusion(:resource_type, ["User", "Group"])
    |> validate_inclusion(:operation, ["create", "update", "delete"])
    |> validate_inclusion(:status, ["pending", "success", "failed"])
  end

  @doc false
  def update_changeset(sync_log, attrs) do
    sync_log
    |> cast(attrs, [
      :status,
      :http_status,
      :request_body,
      :response_body,
      :error_message,
      :retry_count,
      :next_retry_at
    ])
    |> validate_required([:status])
    |> validate_inclusion(:status, ["pending", "success", "failed"])
  end
end
