defmodule AuthifyWeb.Audit.OAuth do
  @moduledoc """
  Centralized audit logging for OAuth operations.

  Provides consistent logging helpers for OAuth authorization and token
  operations, reducing code duplication across grant handlers.
  """

  alias Authify.AuditLog
  alias AuthifyWeb.Audit.Base

  @doc """
  Logs a successful OAuth token grant (authorization_code, client_credentials,
  refresh_token).

  ## Options

    * `:has_refresh_token` - Whether a refresh token was issued (default: false)
    * `:pkce_used` - Whether PKCE was used (default: false)
    * `:application_type` - Application type override (default: nil)
  """
  def log_token_grant_success(
        conn,
        organization,
        application,
        access_token,
        grant_type,
        opts \\ []
      ) do
    has_refresh_token = Keyword.get(opts, :has_refresh_token, false)
    pkce_used = Keyword.get(opts, :pkce_used, false)
    application_type = Keyword.get(opts, :application_type)

    event_type =
      case grant_type do
        "refresh_token" -> :oauth_token_refreshed
        _ -> :oauth_token_granted
      end

    metadata =
      %{
        grant_type: grant_type,
        application_id: application.id,
        application_name: application.name,
        scopes: access_token.scopes
      }
      |> maybe_add_metadata(:has_refresh_token, has_refresh_token)
      |> maybe_add_metadata(:pkce_used, pkce_used)
      |> maybe_add_metadata(:application_type, application_type)

    AuditLog.log_event_async(event_type, %{
      organization_id: organization.id,
      actor_type: "application",
      actor_id: application.id,
      actor_name: application.name,
      resource_type: "oauth_token",
      resource_id: access_token.id,
      outcome: "success",
      ip_address: Base.get_ip_address(conn),
      user_agent: Base.get_user_agent(conn),
      metadata: metadata
    })
  end

  @doc """
  Logs a failed OAuth token grant attempt.
  """
  def log_token_grant_failure(conn, organization, params, error, grant_type) do
    AuditLog.log_event_async(:oauth_token_denied, %{
      organization_id: organization.id,
      actor_type: "application",
      actor_name: params["client_id"],
      outcome: "failure",
      ip_address: Base.get_ip_address(conn),
      user_agent: Base.get_user_agent(conn),
      metadata: %{
        grant_type: grant_type,
        error: to_string(error),
        client_id: params["client_id"]
      }
    })
  end

  @doc """
  Logs a successful OAuth authorization (user consent approval).
  """
  def log_authorization_success(
        conn,
        organization,
        user,
        application,
        auth_code,
        scopes,
        redirect_uri,
        pkce_params
      ) do
    AuditLog.log_event_async(:oauth_authorization_granted, %{
      organization_id: organization.id,
      actor_type: "user",
      actor_id: user.id,
      actor_name: Base.build_user_name(user),
      resource_type: "oauth_authorization",
      resource_id: auth_code.id,
      outcome: "success",
      ip_address: Base.get_ip_address(conn),
      user_agent: Base.get_user_agent(conn),
      metadata: %{
        application_id: application.id,
        application_name: application.name,
        scopes: scopes,
        redirect_uri: redirect_uri,
        pkce_used: Map.has_key?(pkce_params, :code_challenge)
      }
    })
  end

  @doc """
  Logs an auto-approved OAuth authorization (existing grant, skipped consent).
  """
  def log_authorization_auto_approved(
        conn,
        organization,
        user,
        application,
        auth_code,
        scopes,
        redirect_uri,
        pkce_params
      ) do
    AuditLog.log_event_async(:oauth_authorization_auto_approved, %{
      organization_id: organization.id,
      actor_type: "user",
      actor_id: user.id,
      actor_name: Base.build_user_name(user),
      resource_type: "oauth_authorization",
      resource_id: auth_code.id,
      outcome: "success",
      ip_address: Base.get_ip_address(conn),
      user_agent: Base.get_user_agent(conn),
      metadata: %{
        application_id: application.id,
        application_name: application.name,
        scopes: scopes,
        redirect_uri: redirect_uri,
        pkce_used: Map.has_key?(pkce_params, :code_challenge),
        auto_approved: true
      }
    })
  end

  @doc """
  Logs a denied OAuth authorization (user rejected consent).
  """
  def log_authorization_denied(conn, organization, user, params) do
    AuditLog.log_event_async(:oauth_authorization_denied, %{
      organization_id: organization.id,
      actor_type: "user",
      actor_id: user.id,
      actor_name: Base.build_user_name(user),
      outcome: "denied",
      ip_address: Base.get_ip_address(conn),
      user_agent: Base.get_user_agent(conn),
      metadata: %{
        client_id: params["client_id"],
        redirect_uri: params["redirect_uri"]
      }
    })
  end

  @doc """
  Logs a generic OAuth application lifecycle event.
  """
  def log_application_event(conn, event_type, application, metadata, opts \\ []) do
    Base.log_event_async(
      conn,
      event_type,
      opts[:resource_type] || "oauth_application",
      application.id,
      opts[:outcome] || "success",
      Map.merge(metadata, %{
        "application_name" => application.name,
        "application_id" => application.id
      })
    )
  end

  @doc """
  Logs a generic application group lifecycle event.
  """
  def log_application_group_event(conn, event_type, group, opts \\ []) do
    metadata =
      %{
        "group_id" => group.id,
        "group_name" => group.name,
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> Base.maybe_put("description", group.description)
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      event_type,
      opts[:resource_type] || "application_group",
      opts[:resource_id] || group.id,
      opts[:outcome] || "success",
      metadata
    )
  end

  defp maybe_add_metadata(metadata, _key, nil), do: metadata
  defp maybe_add_metadata(metadata, _key, false), do: metadata

  defp maybe_add_metadata(metadata, key, value) do
    Map.put(metadata, key, value)
  end
end
