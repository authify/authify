defmodule AuthifyWeb.Helpers.AuditHelper do
  @moduledoc """
  Helper functions for audit logging in controllers and APIs.

  Provides helpers for recording generic events, configuration updates, and
  certificate lifecycle actions with consistent metadata.
  """

  alias Authify.Accounts.{Invitation, PersonalAccessToken, User}
  alias Authify.AuditLog
  alias Authify.Repo
  alias Ecto.Changeset
  alias Plug.Conn

  @rate_limit_fields MapSet.new(~w(
    quota_auth_rate_limit
    quota_oauth_rate_limit
    quota_saml_rate_limit
    quota_api_rate_limit
    auth_rate_limit
    oauth_rate_limit
    saml_rate_limit
    api_rate_limit
  ))

  @sensitive_fields MapSet.new(~w(smtp_password))
  @user_profile_fields ~w(first_name last_name username theme_preference)a

  @doc """
  Logs an audit event using the connection assigns to determine actor metadata.
  """
  def log_event_async(conn, event_type, resource_type, resource_id, outcome, metadata \\ %{}) do
    organization = conn.assigns.current_organization
    actor_type = conn.assigns[:actor_type] || :user

    base_attrs = %{
      organization_id: organization.id,
      resource_type: resource_type,
      resource_id: resource_id,
      outcome: outcome,
      ip_address: get_ip_address(conn),
      user_agent: get_user_agent(conn),
      metadata: metadata
    }

    attrs =
      case actor_type do
        :user ->
          user = ensure_user_emails_loaded(conn.assigns.current_user)

          Map.merge(base_attrs, %{
            actor_type: "user",
            actor_id: user.id,
            actor_name: build_user_name(user)
          })

        :application ->
          application = conn.assigns.current_application

          Map.merge(base_attrs, %{
            actor_type: "application",
            actor_id: application.id,
            actor_name: application.name
          })
      end

    AuditLog.log_event_async(event_type, attrs)
  end

  @doc """
  Logs a configuration change event, summarizing differences between settings.
  """
  def log_configuration_update(conn, schema_name, old_settings, new_settings, opts \\ []) do
    rate_limit_fields = kwargs_to_set(opts[:rate_limit_fields], @rate_limit_fields)
    sensitive_fields = kwargs_to_set(opts[:sensitive_fields], @sensitive_fields)

    changes = diff_settings(old_settings, new_settings, sensitive_fields)

    if changes != [] do
      rate_limit_changes =
        Enum.filter(changes, fn %{"field" => field} ->
          MapSet.member?(rate_limit_fields, field)
        end)

      metadata =
        %{
          "schema" => schema_name,
          "organization_slug" => conn.assigns.current_organization.slug,
          "changes" => changes
        }
        |> maybe_put("rate_limit_changes", rate_limit_changes)
        |> maybe_merge(opts[:extra_metadata])

      log_event_async(
        conn,
        :settings_updated,
        opts[:resource_type] || "configuration",
        opts[:resource_id] || conn.assigns.current_organization.id,
        opts[:outcome] || "success",
        metadata
      )
    else
      :noop
    end
  end

  @doc """
  Logs a failed configuration update attempt with error details.
  """
  def log_configuration_update_failure(conn, schema_name, errors, opts \\ []) do
    metadata =
      %{
        "schema" => schema_name,
        "organization_slug" => conn.assigns.current_organization.slug,
        "errors" => List.wrap(errors)
      }
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
      conn,
      :settings_updated,
      opts[:resource_type] || "configuration",
      opts[:resource_id] || conn.assigns.current_organization.id,
      "failure",
      metadata
    )
  end

  @doc """
  Logs certificate lifecycle events (creation, activation, deactivation, deletion).
  """
  def log_certificate_event(conn, event_type, certificate, opts \\ []) do
    metadata =
      %{
        "certificate_id" => certificate.id,
        "certificate_name" => certificate.name,
        "usage" => certificate.usage,
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> maybe_put_generated(opts[:generated])
      |> maybe_put_previous_state(opts[:previous_state])
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
      conn,
      event_type,
      opts[:resource_type] || "certificate",
      opts[:resource_id] || certificate.id,
      opts[:outcome] || "success",
      metadata
    )
  end

  @doc """
  Logs failed certificate lifecycle attempts with error details.
  """
  def log_certificate_failure(conn, event_type, errors, opts \\ []) do
    certificate = opts[:certificate]

    metadata =
      %{
        "errors" => normalize_errors(errors),
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> maybe_merge(opts[:extra_metadata])
      |> maybe_attach_certificate(certificate)

    log_event_async(
      conn,
      event_type,
      opts[:resource_type] || "certificate",
      opts[:resource_id] || maybe_certificate_id(certificate),
      "failure",
      metadata
    )
  end

  @doc """
  Logs personal access token lifecycle events (creation, deletion, etc.).
  """
  def log_personal_access_token_event(conn, event_type, token, opts \\ []) do
    metadata =
      %{
        "personal_access_token_id" => token.id,
        "personal_access_token_name" => token.name,
        "user_id" => token.user_id,
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> maybe_put("description", token.description)
      |> maybe_put("scopes", personal_access_token_scopes(token))
      |> maybe_put("expires_at", normalize_value(token.expires_at))
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
      conn,
      event_type,
      opts[:resource_type] || "personal_access_token",
      opts[:resource_id] || token.id,
      opts[:outcome] || "success",
      metadata
    )
  end

  @doc """
  Logs failed personal access token operations with error details.
  """
  def log_personal_access_token_failure(conn, event_type, errors, opts \\ []) do
    token = opts[:personal_access_token]

    metadata =
      %{
        "errors" => normalize_errors(errors),
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> maybe_merge(opts[:extra_metadata])
      |> maybe_attach_personal_access_token(token)

    log_event_async(
      conn,
      event_type,
      opts[:resource_type] || "personal_access_token",
      opts[:resource_id] || maybe_personal_access_token_id(token),
      "failure",
      metadata
    )
  end

  @doc """
  Logs successful invitation creation or resend events.
  """
  def log_invitation_sent(conn, invitation, opts \\ []) do
    conn = ensure_current_organization(conn, invitation.organization)

    metadata =
      invitation_metadata(invitation)
      |> maybe_put("invited_by_user_id", invitation.invited_by_id)
      |> maybe_put("resend", normalize_resend_flag(opts[:resend?]))
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
      conn,
      :user_invited,
      opts[:resource_type] || "invitation",
      opts[:resource_id] || invitation.id,
      opts[:outcome] || "success",
      metadata
    )
  end

  @doc """
  Logs failed attempts to send invitations.
  """
  def log_invitation_send_failure(conn, errors, opts \\ []) do
    invitation_context =
      opts[:invitation] ||
        opts[:invitation_changeset] ||
        opts[:invitation_attrs]

    base_metadata =
      case conn.assigns[:current_organization] do
        %{slug: slug} -> %{"organization_slug" => slug}
        _ -> %{}
      end

    metadata =
      base_metadata
      |> Map.put("errors", normalize_errors(errors))
      |> maybe_attach_invitation(invitation_context)
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
      conn,
      :user_invited,
      opts[:resource_type] || "invitation",
      opts[:resource_id],
      "failure",
      metadata
    )
  end

  @doc """
  Logs invitation revocation/cancellation events.
  """
  def log_invitation_revoked(conn, invitation, opts \\ []) do
    conn = ensure_current_organization(conn, invitation.organization)

    metadata =
      invitation_metadata(invitation)
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
      conn,
      :invitation_revoked,
      opts[:resource_type] || "invitation",
      opts[:resource_id] || invitation.id,
      opts[:outcome] || "success",
      metadata
    )
  end

  @doc """
  Logs successful invitation acceptance events.
  """
  def log_invitation_accepted(conn, invitation, user, opts \\ []) do
    conn =
      conn
      |> assign_actor_from_user(user)
      |> ensure_current_organization(invitation.organization)

    metadata =
      invitation_metadata(invitation)
      |> maybe_put("user_id", user.id)
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
      conn,
      :user_invitation_accepted,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      opts[:outcome] || "success",
      metadata
    )
  end

  @doc """
  Logs successful password reset completions.
  """
  def log_password_reset_completed(conn, user, opts \\ []) do
    user = ensure_user_emails_loaded(user)
    conn = assign_actor_from_user(conn, user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "organization_slug" => user.organization.slug
      }
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
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
    user = ensure_user_emails_loaded(user)
    conn = assign_actor_from_user(conn, user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "organization_slug" => user.organization.slug,
        "reason" => to_string(reason)
      }
      |> maybe_put("errors", normalize_errors(opts[:errors]))
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
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
    user = ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email_id" => email.id,
        "email_value" => email.value,
        "email_type" => email.type,
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
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
    user = ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email_id" => email.id,
        "email_value" => email.value,
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
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
    user = ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "new_primary_email_id" => email.id,
        "new_primary_email_value" => email.value,
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
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
    user = ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
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
    user = ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "organization_slug" => conn.assigns.current_organization.slug,
        "reason" => to_string(reason)
      }
      |> maybe_put("errors", normalize_errors(opts[:errors]))
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
      conn,
      :email_verification_resent,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      "failure",
      metadata
    )
  end

  @doc """
  Logs profile updates for the current user, capturing changed fields.
  """
  def log_user_profile_update(conn, old_user, new_user, opts \\ []) do
    old_user = ensure_user_emails_loaded(old_user)
    new_user = ensure_user_emails_loaded(new_user)

    fields = opts[:fields] || @user_profile_fields
    sensitive_fields = kwargs_to_set(opts[:sensitive_fields], MapSet.new())

    changes = diff_struct_fields(old_user, new_user, fields, sensitive_fields)

    metadata =
      %{
        "user_id" => new_user.id,
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> maybe_put("changes", changes)
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
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
    user = ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "organization_slug" => conn.assigns.current_organization.slug,
        "errors" => normalize_errors(errors)
      }
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
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
    user = ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
      conn,
      :password_changed,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      opts[:outcome] || "success",
      metadata
    )
  end

  @doc """
  Logs successful user creation events (admin-initiated).
  """
  def log_user_created(conn, user, opts \\ []) do
    user = ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "role" => user.role,
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> maybe_put("first_name", user.first_name)
      |> maybe_put("last_name", user.last_name)
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
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
    user = ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "role" => user.role,
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> maybe_put("first_name", user.first_name)
      |> maybe_put("last_name", user.last_name)
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
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
    user = ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "old_role" => old_role,
        "new_role" => new_role,
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
      conn,
      :role_assigned,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      "success",
      metadata
    )
  end

  @doc """
  Logs SAML service provider lifecycle events (creation, update, deletion).
  """
  def log_saml_provider_event(conn, event_type, service_provider, opts \\ []) do
    metadata =
      %{
        "service_provider_id" => service_provider.id,
        "service_provider_name" => service_provider.name,
        "entity_id" => service_provider.entity_id,
        "acs_url" => service_provider.acs_url,
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
      conn,
      event_type,
      opts[:resource_type] || "saml_service_provider",
      opts[:resource_id] || service_provider.id,
      opts[:outcome] || "success",
      metadata
    )
  end

  @doc """
  Logs application group lifecycle events (creation, update, deletion).
  """
  def log_application_group_event(conn, event_type, group, opts \\ []) do
    metadata =
      %{
        "group_id" => group.id,
        "group_name" => group.name,
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> maybe_put("description", group.description)
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
      conn,
      event_type,
      opts[:resource_type] || "application_group",
      opts[:resource_id] || group.id,
      opts[:outcome] || "success",
      metadata
    )
  end

  @doc """
  Logs failed password change attempts.
  """
  def log_password_change_failure(conn, user, errors, opts \\ []) do
    user = ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "organization_slug" => conn.assigns.current_organization.slug,
        "errors" => normalize_errors(errors)
      }
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
      conn,
      :password_changed,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      "failure",
      metadata
    )
  end

  @doc """
  Logs successful MFA enablement events.
  """
  def log_mfa_enabled(conn, user, opts \\ []) do
    user = ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
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
    user = ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
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
    user = ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "organization_slug" => user.organization.slug
      }
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
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
    user = ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "organization_slug" => user.organization.slug
      }
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
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
    user = ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
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
    user = ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
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
    user = ensure_user_emails_loaded(user)

    metadata =
      %{
        "user_id" => user.id,
        "email" => User.get_primary_email_value(user),
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> maybe_merge(opts[:extra_metadata])

    log_event_async(
      conn,
      :mfa_all_devices_revoked,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      "success",
      metadata
    )
  end

  @doc """
  Converts changeset errors into a flat list of human-readable strings.
  """
  def changeset_errors(%Changeset{} = changeset) do
    changeset
    |> Changeset.traverse_errors(&translate_error/1)
    |> Enum.flat_map(fn {field, messages} ->
      Enum.map(List.wrap(messages), fn message ->
        "#{field} #{message}"
      end)
    end)
  end

  @doc """
  Extracts the originating IP address from the connection.
  """
  def get_ip_address(conn) do
    case Plug.Conn.get_req_header(conn, "x-forwarded-for") do
      [ip | _] -> ip
      [] -> to_string(:inet_parse.ntoa(conn.remote_ip))
    end
  end

  @doc """
  Extracts the user agent from the connection.
  """
  def get_user_agent(conn) do
    case Plug.Conn.get_req_header(conn, "user-agent") do
      [user_agent | _] -> user_agent
      [] -> "Unknown"
    end
  end

  defp build_user_name(user) do
    cond do
      user.first_name && user.last_name -> "#{user.first_name} #{user.last_name}"
      user.first_name -> user.first_name
      user.last_name -> user.last_name
      true -> User.get_primary_email_value(user)
    end
  end

  defp diff_settings(old_settings, new_settings, sensitive_fields) do
    keys =
      Map.keys(old_settings)
      |> Enum.concat(Map.keys(new_settings))
      |> Enum.uniq()

    keys
    |> Enum.reduce([], fn key, acc ->
      old_val = Map.get(old_settings, key)
      new_val = Map.get(new_settings, key)

      if old_val == new_val do
        acc
      else
        field = to_string(key)

        change = %{
          "field" => field,
          "old" => mask_sensitive(field, normalize_value(old_val), sensitive_fields),
          "new" => mask_sensitive(field, normalize_value(new_val), sensitive_fields)
        }

        [change | acc]
      end
    end)
    |> Enum.reverse()
  end

  defp diff_struct_fields(old_struct, new_struct, fields, sensitive_fields) do
    old_map = extract_fields(old_struct, fields)
    new_map = extract_fields(new_struct, fields)

    fields
    |> Enum.reduce([], fn field, acc ->
      old_val = Map.get(old_map, field)
      new_val = Map.get(new_map, field)

      if old_val == new_val do
        acc
      else
        field_str = to_string(field)

        change = %{
          "field" => field_str,
          "old" => mask_sensitive(field_str, normalize_value(old_val), sensitive_fields),
          "new" => mask_sensitive(field_str, normalize_value(new_val), sensitive_fields)
        }

        [change | acc]
      end
    end)
    |> Enum.reverse()
  end

  defp extract_fields(%_{} = struct, fields) do
    struct
    |> Map.from_struct()
    |> extract_fields(fields)
  end

  defp extract_fields(map, fields) when is_map(map) do
    Map.take(map, fields)
  end

  defp normalize_value(nil), do: nil
  defp normalize_value(value) when is_boolean(value) or is_number(value), do: value
  defp normalize_value(value) when is_binary(value), do: value
  defp normalize_value(value) when is_list(value), do: Enum.map(value, &normalize_value/1)

  defp normalize_value(%_{} = struct) do
    struct
    |> Map.from_struct()
    |> normalize_value()
  end

  defp normalize_value(value) when is_map(value) do
    value
    |> Enum.map(fn {key, val} -> {to_string(key), normalize_value(val)} end)
    |> Enum.into(%{})
  end

  defp normalize_value(value), do: inspect(value)

  defp mask_sensitive(field, value, sensitive_fields) do
    if MapSet.member?(sensitive_fields, field) and not is_nil(value) and value != "" do
      "[FILTERED]"
    else
      value
    end
  end

  defp kwargs_to_set(nil, default), do: default
  defp kwargs_to_set(%MapSet{} = set, _default), do: set

  defp kwargs_to_set(values, _default) when is_list(values) do
    values
    |> Enum.map(&to_string/1)
    |> MapSet.new()
  end

  defp kwargs_to_set(_other, default), do: default

  defp maybe_put(map, _key, []), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp maybe_merge(map, nil), do: map

  defp maybe_merge(map, extra) when is_map(extra) do
    Map.merge(map, stringify_keys(extra))
  end

  defp maybe_merge(map, _extra), do: map

  defp stringify_keys(map) do
    map
    |> Enum.map(fn {key, value} -> {to_string(key), normalize_value(value)} end)
    |> Enum.into(%{})
  end

  defp maybe_put_generated(map, nil), do: map
  defp maybe_put_generated(map, value), do: Map.put(map, "generated", value)

  defp maybe_put_previous_state(map, nil), do: map

  defp maybe_put_previous_state(map, value) do
    Map.put(map, "previous_state", normalize_value(value))
  end

  defp maybe_attach_personal_access_token(map, nil), do: map

  defp maybe_attach_personal_access_token(map, token) do
    map
    |> Map.put("personal_access_token_id", token.id)
    |> Map.put("personal_access_token_name", token.name)
    |> maybe_put("user_id", token.user_id)
    |> maybe_put("description", token.description)
    |> maybe_put("scopes", personal_access_token_scopes(token))
    |> maybe_put("expires_at", normalize_value(token.expires_at))
  end

  defp maybe_attach_certificate(map, nil), do: map

  defp maybe_attach_certificate(map, certificate) do
    map
    |> Map.put("certificate_id", certificate.id)
    |> Map.put("certificate_name", certificate.name)
    |> maybe_put_usage(certificate.usage)
  end

  defp maybe_attach_invitation(map, nil), do: map

  defp maybe_attach_invitation(map, %Invitation{} = invitation) do
    Map.merge(map, invitation_metadata(invitation))
  end

  defp maybe_attach_invitation(map, %Changeset{} = changeset) do
    map
    |> maybe_put("invited_email", Changeset.get_field(changeset, :email))
    |> maybe_put("invited_role", Changeset.get_field(changeset, :role))
    |> maybe_put("organization_id", Changeset.get_field(changeset, :organization_id))
    |> maybe_put("expires_at", normalize_value(Changeset.get_field(changeset, :expires_at)))
  end

  defp maybe_attach_invitation(map, %{} = attrs) do
    map
    |> maybe_put("invitation_id", Map.get(attrs, :id) || Map.get(attrs, "id"))
    |> maybe_put("invited_email", Map.get(attrs, :email) || Map.get(attrs, "email"))
    |> maybe_put("invited_role", Map.get(attrs, :role) || Map.get(attrs, "role"))
    |> maybe_put(
      "organization_id",
      Map.get(attrs, :organization_id) || Map.get(attrs, "organization_id")
    )
    |> maybe_put(
      "expires_at",
      normalize_value(Map.get(attrs, :expires_at) || Map.get(attrs, "expires_at"))
    )
  end

  defp invitation_metadata(invitation) do
    %{
      "invitation_id" => invitation.id,
      "invited_email" => invitation.email,
      "invited_role" => invitation.role,
      "organization_slug" => organization_slug(invitation),
      "expires_at" => normalize_value(invitation.expires_at)
    }
    |> maybe_put("invited_by_user_id", invitation.invited_by_id)
    |> maybe_put("accepted_at", normalize_value(invitation.accepted_at))
  end

  defp organization_slug(%{organization: %{slug: slug}}), do: slug
  defp organization_slug(_), do: nil

  defp maybe_put_usage(map, nil), do: map
  defp maybe_put_usage(map, usage), do: Map.put(map, "usage", usage)

  defp maybe_certificate_id(nil), do: nil
  defp maybe_certificate_id(%{id: id}), do: id

  defp maybe_personal_access_token_id(nil), do: nil
  defp maybe_personal_access_token_id(%{id: id}), do: id

  defp personal_access_token_scopes(%PersonalAccessToken{} = token) do
    case PersonalAccessToken.scopes_list(token) do
      [] -> nil
      scopes -> scopes
    end
  end

  defp personal_access_token_scopes(_), do: nil

  defp ensure_user_emails_loaded(nil), do: nil

  defp ensure_user_emails_loaded(%User{emails: %Ecto.Association.NotLoaded{}} = user) do
    Repo.preload(user, :emails)
  end

  defp ensure_user_emails_loaded(%User{emails: emails} = user) when is_list(emails), do: user

  defp ensure_user_emails_loaded(%User{} = user), do: Repo.preload(user, :emails)

  defp ensure_current_organization(conn, nil), do: conn

  defp ensure_current_organization(conn, organization) do
    case conn.assigns[:current_organization] do
      nil -> Conn.assign(conn, :current_organization, organization)
      _ -> conn
    end
  end

  defp normalize_resend_flag(nil), do: []
  defp normalize_resend_flag(value) when is_boolean(value), do: value
  defp normalize_resend_flag(value), do: to_string(value)

  defp assign_actor_from_user(conn, user) do
    user = ensure_user_emails_loaded(user)

    conn
    |> Conn.assign(:actor_type, :user)
    |> Conn.assign(:current_user, user)
    |> Conn.assign(:current_organization, user.organization)
  end

  defp normalize_errors(errors) when is_binary(errors), do: [errors]
  defp normalize_errors(errors) when is_list(errors), do: Enum.map(errors, &to_string/1)
  defp normalize_errors(%Changeset{} = changeset), do: changeset_errors(changeset)
  defp normalize_errors(nil), do: []
  defp normalize_errors(other), do: [inspect(other)]

  defp translate_error({msg, opts}) do
    Enum.reduce(opts, msg, fn {key, value}, acc ->
      String.replace(acc, "%{#{key}}", to_string(value))
    end)
  end
end
