defmodule AuthifyWeb.Audit.Users do
  @moduledoc """
  Audit logging for user lifecycle and profile events.
  """

  alias Authify.Accounts.User
  alias AuthifyWeb.Audit.Base

  @user_profile_fields ~w(first_name last_name username theme_preference)a

  @doc """
  Logs profile updates for the current user, capturing changed fields.
  """
  def log_user_profile_update(conn, old_user, new_user, opts \\ []) do
    old_user = Base.ensure_user_emails_loaded(old_user)
    new_user = Base.ensure_user_emails_loaded(new_user)

    fields = opts[:fields] || @user_profile_fields
    sensitive_fields = Base.kwargs_to_set(opts[:sensitive_fields], MapSet.new())

    changes = Base.diff_struct_fields(old_user, new_user, fields, sensitive_fields)

    metadata =
      %{
        "user_id" => new_user.id,
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> Base.maybe_put("changes", changes)
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      :user_updated,
      opts[:resource_type] || "user",
      opts[:resource_id] || new_user.id,
      opts[:outcome] || "success",
      metadata
    )
  end

  @doc """
  Logs failed attempts to update a user profile.
  """
  def log_user_profile_failure(conn, user, errors, opts \\ []) do
    user = Base.ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "organization_slug" => conn.assigns.current_organization.slug,
        "errors" => Base.normalize_errors(errors)
      }
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      :user_updated,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      "failure",
      metadata
    )
  end

  @doc """
  Logs successful password change attempts.
  """
  def log_password_change(conn, user, opts \\ []) do
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
      :password_changed,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      opts[:outcome] || "success",
      metadata
    )
  end

  @doc """
  Logs failed password change attempts.
  """
  def log_password_change_failure(conn, user, errors, opts \\ []) do
    user = Base.ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "organization_slug" => conn.assigns.current_organization.slug,
        "errors" => Base.normalize_errors(errors)
      }
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      :password_changed,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      "failure",
      metadata
    )
  end

  @doc """
  Logs successful user creation events (admin-initiated).
  """
  def log_user_created(conn, user, opts \\ []) do
    user = Base.ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "role" => user.role,
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> Base.maybe_put("first_name", user.first_name)
      |> Base.maybe_put("last_name", user.last_name)
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      :user_created,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      "success",
      metadata
    )
  end

  @doc """
  Logs successful user deletion events (admin-initiated).
  """
  def log_user_deleted(conn, user, opts \\ []) do
    user = Base.ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "role" => user.role,
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> Base.maybe_put("first_name", user.first_name)
      |> Base.maybe_put("last_name", user.last_name)
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      :user_deleted,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      "success",
      metadata
    )
  end

  @doc """
  Logs role assignment/changes for users.
  """
  def log_role_assigned(conn, user, old_role, new_role, opts \\ []) do
    user = Base.ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "old_role" => old_role,
        "new_role" => new_role,
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      :role_assigned,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      "success",
      metadata
    )
  end

  @doc """
  Logs successful password reset completions.
  """
  def log_password_reset_completed(conn, user, opts \\ []) do
    user = Base.ensure_user_emails_loaded(user)
    conn = Base.assign_actor_from_user(conn, user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "organization_slug" => user.organization.slug
      }
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      :password_reset_completed,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      "success",
      metadata
    )
  end

  @doc """
  Logs failed password reset attempts when the user is known.
  """
  def log_password_reset_failure(conn, user, reason, opts \\ []) do
    user = Base.ensure_user_emails_loaded(user)
    conn = Base.assign_actor_from_user(conn, user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "organization_slug" => user.organization.slug,
        "reason" => to_string(reason)
      }
      |> Base.maybe_put("errors", Base.normalize_errors(opts[:errors]))
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      :password_reset_completed,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      "failure",
      metadata
    )
  end

  @doc """
  Logs when a user adds a new email address.
  """
  def log_email_added(conn, user, email, opts \\ []) do
    user = Base.ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email_id" => email.id,
        "email_value" => email.value,
        "email_type" => email.type,
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      :email_added,
      opts[:resource_type] || "user_email",
      opts[:resource_id] || email.id,
      "success",
      metadata
    )
  end

  @doc """
  Logs when a user deletes an email address.
  """
  def log_email_deleted(conn, user, email, opts \\ []) do
    user = Base.ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email_id" => email.id,
        "email_value" => email.value,
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      :email_deleted,
      opts[:resource_type] || "user_email",
      opts[:resource_id] || email.id,
      "success",
      metadata
    )
  end

  @doc """
  Logs when a user changes their primary email address.
  """
  def log_primary_email_changed(conn, user, email, opts \\ []) do
    user = Base.ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "new_primary_email_id" => email.id,
        "new_primary_email_value" => email.value,
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      :primary_email_changed,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      "success",
      metadata
    )
  end

  @doc """
  Logs successful email verification resend events.
  """
  def log_email_verification_resent(conn, user, opts \\ []) do
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
      :email_verification_resent,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      "success",
      metadata
    )
  end

  @doc """
  Logs failed email verification resend attempts.
  """
  def log_email_verification_resend_failure(conn, user, reason, opts \\ []) do
    user = Base.ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "organization_slug" => conn.assigns.current_organization.slug,
        "reason" => to_string(reason)
      }
      |> Base.maybe_put("errors", Base.normalize_errors(opts[:errors]))
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      :email_verification_resent,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      "failure",
      metadata
    )
  end

  @doc """
  Logs a generic user event with custom event type and metadata.
  """
  def log_user_event(conn, event_type, target_user, metadata, opts \\ []) do
    Base.log_event_async(
      conn,
      event_type,
      opts[:resource_type] || "user",
      target_user && target_user.id,
      opts[:outcome] || "success",
      metadata
    )
  end
end
