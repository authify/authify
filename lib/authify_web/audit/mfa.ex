defmodule AuthifyWeb.Audit.MFA do
  @moduledoc """
  Audit logging for multi-factor authentication events.
  """

  alias Authify.Accounts.User
  alias AuthifyWeb.Audit.Base

  @doc """
  Logs successful MFA enablement events.
  """
  def log_mfa_enabled(conn, user, opts \\ []) do
    user = Base.ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      :mfa_enabled,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      "success",
      metadata
    )
  end

  @doc """
  Logs successful MFA disablement events.
  """
  def log_mfa_disabled(conn, user, opts \\ []) do
    user = Base.ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      :mfa_disabled,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      "success",
      metadata
    )
  end

  @doc """
  Logs successful MFA verification events during login.
  """
  def log_mfa_verified(conn, user, opts \\ []) do
    user = Base.ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "organization_slug" => user.organization.slug
      }
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      :mfa_verified,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      "success",
      metadata
    )
  end

  @doc """
  Logs failed MFA verification attempts during login.
  """
  def log_mfa_failed(conn, user, opts \\ []) do
    user = Base.ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "organization_slug" => user.organization.slug
      }
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      :mfa_failed,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      "failure",
      metadata
    )
  end

  @doc """
  Logs backup code regeneration events.
  """
  def log_mfa_backup_codes_regenerated(conn, user, opts \\ []) do
    user = Base.ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      :mfa_backup_codes_regenerated,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      "success",
      metadata
    )
  end

  @doc """
  Logs trusted device revocation events.
  """
  def log_mfa_device_revoked(conn, user, opts \\ []) do
    user = Base.ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      :mfa_device_revoked,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      "success",
      metadata
    )
  end

  @doc """
  Logs events where all trusted devices are revoked.
  """
  def log_mfa_all_devices_revoked(conn, user, opts \\ []) do
    user = Base.ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      :mfa_all_devices_revoked,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      "success",
      metadata
    )
  end
end
