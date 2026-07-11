defmodule AuthifyWeb.OAuthController.AuditLogger do
  @moduledoc """
  Backward-compatible facade delegating to `AuthifyWeb.Audit.OAuth`.

  This module exists to keep existing references working while the codebase
  migrates to the new `AuthifyWeb.Audit.*` convention. New code should call
  `AuthifyWeb.Audit.OAuth` directly.
  """

  alias AuthifyWeb.Audit.OAuth

  defdelegate log_token_grant_success(
                conn,
                organization,
                application,
                access_token,
                grant_type,
                opts \\ []
              ),
              to: OAuth

  defdelegate log_token_grant_failure(conn, organization, params, error, grant_type),
    to: OAuth

  defdelegate log_authorization_success(
                conn,
                organization,
                user,
                application,
                auth_code,
                scopes,
                redirect_uri,
                pkce_params
              ),
              to: OAuth

  defdelegate log_authorization_auto_approved(
                conn,
                organization,
                user,
                application,
                auth_code,
                scopes,
                redirect_uri,
                pkce_params
              ),
              to: OAuth

  defdelegate log_authorization_denied(conn, organization, user, params), to: OAuth
end
