defmodule Authify.AuditLog.Event do
  @moduledoc """
  Schema for security and authentication audit events.

  Tracks events such as logins, OAuth grants, SAML SSO, password resets,
  and other security-relevant actions in the system.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Authify.Accounts.Organization

  @event_types ~w(
    login_success login_failure
    logout session_expired
    password_reset_requested password_reset_completed password_changed
    oauth_authorization_requested oauth_authorization_granted oauth_authorization_denied
    oauth_consent_given oauth_token_granted oauth_token_denied oauth_token_refreshed
    saml_sso_requested saml_assertion_issued saml_slo_requested saml_slo_completed
    user_created user_updated user_deleted user_enabled user_disabled
    user_invited user_invitation_accepted invitation_revoked
    role_assigned role_revoked
    oauth_client_created oauth_client_updated oauth_client_deleted oauth_client_secret_regenerated
    saml_sp_created saml_sp_updated saml_sp_deleted
    organization_created organization_updated organization_deleted
    certificate_created certificate_activated certificate_deactivated certificate_deleted
    settings_updated
    rate_limit_exceeded
    permission_denied scope_denied
    api_access api_key_created api_key_revoked
    suspicious_activity
  )a

  @actor_types ~w(user api_client application system)a
  @outcome_types ~w(success failure denied)a

  schema "audit_events" do
    field :event_type, :string
    field :actor_type, :string
    field :actor_id, :integer
    field :actor_name, :string
    field :resource_type, :string
    field :resource_id, :integer
    field :ip_address, :string
    field :user_agent, :string
    field :outcome, :string
    field :metadata, :map

    belongs_to :organization, Organization

    timestamps(updated_at: false, type: :utc_datetime)
  end

  @doc false
  def changeset(event, attrs) do
    event
    |> cast(attrs, [
      :event_type,
      :actor_type,
      :actor_id,
      :actor_name,
      :resource_type,
      :resource_id,
      :organization_id,
      :ip_address,
      :user_agent,
      :outcome,
      :metadata
    ])
    |> validate_required([:event_type, :actor_type, :outcome, :organization_id])
    |> validate_inclusion(:event_type, Enum.map(@event_types, &to_string/1))
    |> validate_inclusion(:actor_type, Enum.map(@actor_types, &to_string/1))
    |> validate_inclusion(:outcome, Enum.map(@outcome_types, &to_string/1))
    |> foreign_key_constraint(:organization_id)
  end

  @doc """
  Returns the list of valid event types.
  """
  def event_types, do: @event_types

  @doc """
  Returns the list of valid actor types.
  """
  def actor_types, do: @actor_types

  @doc """
  Returns the list of valid outcome types.
  """
  def outcome_types, do: @outcome_types
end
