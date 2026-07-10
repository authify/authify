defmodule AuthifyWeb.Helpers.AuditHelper do
  @moduledoc """
  Backward-compatible facade delegating to the domain-specific audit modules
  under `AuthifyWeb.Audit.*`.

  This module exists to keep existing call sites working while the codebase
  migrates to the new convention. New code should call the domain modules
  directly instead of going through this facade.
  """

  alias AuthifyWeb.Audit.Base
  alias AuthifyWeb.Audit.Certificates
  alias AuthifyWeb.Audit.Configuration
  alias AuthifyWeb.Audit.Invitations
  alias AuthifyWeb.Audit.MFA
  alias AuthifyWeb.Audit.OAuth
  alias AuthifyWeb.Audit.Users

  # Generic event logging -----------------------------------------------------

  defdelegate log_event_async(
                conn,
                event_type,
                resource_type,
                resource_id,
                outcome,
                metadata \\ %{}
              ),
              to: Base

  # Configuration -------------------------------------------------------------

  defdelegate log_configuration_update(conn, schema_name, old_settings, new_settings, opts \\ []),
    to: Configuration

  defdelegate log_configuration_update_failure(conn, schema_name, errors, opts \\ []),
    to: Configuration

  # Certificates and personal access tokens ----------------------------------

  defdelegate log_certificate_event(conn, event_type, certificate, opts \\ []), to: Certificates

  defdelegate log_certificate_failure(conn, event_type, errors, opts \\ []), to: Certificates

  defdelegate log_personal_access_token_event(conn, event_type, token, opts \\ []),
    to: Certificates

  defdelegate log_personal_access_token_failure(conn, event_type, errors, opts \\ []),
    to: Certificates

  # Invitations ---------------------------------------------------------------

  defdelegate log_invitation_sent(conn, invitation, opts \\ []), to: Invitations

  defdelegate log_invitation_send_failure(conn, errors, opts \\ []), to: Invitations

  defdelegate log_invitation_revoked(conn, invitation, opts \\ []), to: Invitations

  defdelegate log_invitation_accepted(conn, invitation, user, opts \\ []), to: Invitations

  # Users: password resets ----------------------------------------------------

  defdelegate log_password_reset_completed(conn, user, opts \\ []), to: Users

  defdelegate log_password_reset_failure(conn, user, reason, opts \\ []), to: Users

  # Users: email management ---------------------------------------------------

  defdelegate log_email_added(conn, user, email, opts \\ []), to: Users

  defdelegate log_email_deleted(conn, user, email, opts \\ []), to: Users

  defdelegate log_primary_email_changed(conn, user, email, opts \\ []), to: Users

  defdelegate log_email_verification_resent(conn, user, opts \\ []), to: Users

  defdelegate log_email_verification_resend_failure(conn, user, reason, opts \\ []),
    to: Users

  # Users: profile and password ----------------------------------------------

  defdelegate log_user_profile_update(conn, old_user, new_user, opts \\ []), to: Users

  defdelegate log_user_profile_failure(conn, user, errors, opts \\ []), to: Users

  defdelegate log_password_change(conn, user, opts \\ []), to: Users

  defdelegate log_password_change_failure(conn, user, errors, opts \\ []), to: Users

  defdelegate log_user_created(conn, user, opts \\ []), to: Users

  defdelegate log_user_deleted(conn, user, opts \\ []), to: Users

  defdelegate log_role_assigned(conn, user, old_role, new_role, opts \\ []), to: Users

  # SAML service providers ----------------------------------------------------

  defdelegate log_saml_provider_event(conn, event_type, service_provider, opts \\ []),
    to: AuthifyWeb.Audit.SAML

  # Application groups ---------------------------------------------------------

  defdelegate log_application_group_event(conn, event_type, group, opts \\ []), to: OAuth

  # MFA ------------------------------------------------------------------------

  defdelegate log_mfa_enabled(conn, user, opts \\ []), to: MFA

  defdelegate log_mfa_disabled(conn, user, opts \\ []), to: MFA

  defdelegate log_mfa_verified(conn, user, opts \\ []), to: MFA

  defdelegate log_mfa_failed(conn, user, opts \\ []), to: MFA

  defdelegate log_mfa_backup_codes_regenerated(conn, user, opts \\ []), to: MFA

  defdelegate log_mfa_device_revoked(conn, user, opts \\ []), to: MFA

  defdelegate log_mfa_all_devices_revoked(conn, user, opts \\ []), to: MFA

  # Shared utilities ----------------------------------------------------------

  defdelegate changeset_errors(changeset), to: Base

  defdelegate get_ip_address(conn), to: Base

  defdelegate get_user_agent(conn), to: Base
end
