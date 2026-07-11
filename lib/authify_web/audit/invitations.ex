defmodule AuthifyWeb.Audit.Invitations do
  @moduledoc """
  Audit logging for invitation lifecycle events.
  """

  alias Authify.Accounts.Invitation
  alias AuthifyWeb.Audit.Base
  alias Ecto.Changeset

  @doc """
  Logs successful invitation creation or resend events.
  """
  def log_invitation_sent(conn, invitation, opts \\ []) do
    conn = Base.ensure_current_organization(conn, invitation.organization)

    metadata =
      invitation_metadata(invitation)
      |> Base.maybe_put("invited_by_user_id", invitation.invited_by_id)
      |> Base.maybe_put("resend", normalize_resend_flag(opts[:resend?]))
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
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
      |> Map.put("errors", Base.normalize_errors(errors))
      |> maybe_attach_invitation(invitation_context)
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
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
    conn = Base.ensure_current_organization(conn, invitation.organization)

    metadata =
      invitation_metadata(invitation)
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
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
      |> Base.assign_actor_from_user(user)
      |> Base.ensure_current_organization(invitation.organization)

    metadata =
      invitation_metadata(invitation)
      |> Base.maybe_put("user_id", user.id)
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      :user_invitation_accepted,
      opts[:resource_type] || "user",
      opts[:resource_id] || user.id,
      opts[:outcome] || "success",
      metadata
    )
  end

  defp normalize_resend_flag(nil), do: []
  defp normalize_resend_flag(value) when is_boolean(value), do: value
  defp normalize_resend_flag(value), do: to_string(value)

  defp maybe_attach_invitation(map, nil), do: map

  defp maybe_attach_invitation(map, %Invitation{} = invitation) do
    Map.merge(map, invitation_metadata(invitation))
  end

  defp maybe_attach_invitation(map, %Changeset{} = changeset) do
    map
    |> Base.maybe_put("invited_email", Changeset.get_field(changeset, :email))
    |> Base.maybe_put("invited_role", Changeset.get_field(changeset, :role))
    |> Base.maybe_put("organization_id", Changeset.get_field(changeset, :organization_id))
    |> Base.maybe_put(
      "expires_at",
      Base.normalize_value(Changeset.get_field(changeset, :expires_at))
    )
  end

  defp maybe_attach_invitation(map, %{} = attrs) do
    map
    |> Base.maybe_put("invitation_id", Map.get(attrs, :id) || Map.get(attrs, "id"))
    |> Base.maybe_put("invited_email", Map.get(attrs, :email) || Map.get(attrs, "email"))
    |> Base.maybe_put("invited_role", Map.get(attrs, :role) || Map.get(attrs, "role"))
    |> Base.maybe_put(
      "organization_id",
      Map.get(attrs, :organization_id) || Map.get(attrs, "organization_id")
    )
    |> Base.maybe_put(
      "expires_at",
      Base.normalize_value(Map.get(attrs, :expires_at) || Map.get(attrs, "expires_at"))
    )
  end

  defp invitation_metadata(invitation) do
    %{
      "invitation_id" => invitation.id,
      "invited_email" => invitation.email,
      "invited_role" => invitation.role,
      "organization_slug" => organization_slug(invitation),
      "expires_at" => Base.normalize_value(invitation.expires_at)
    }
    |> Base.maybe_put("invited_by_user_id", invitation.invited_by_id)
    |> Base.maybe_put("accepted_at", Base.normalize_value(invitation.accepted_at))
  end

  defp organization_slug(%{organization: %{slug: slug}}), do: slug
  defp organization_slug(_), do: nil
end
