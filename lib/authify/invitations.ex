defmodule Authify.Invitations do
  @moduledoc """
  Context for managing invitations.
  """

  import Ecto.Query, warn: false

  alias Authify.Accounts.{Invitation, User}
  alias Authify.Repo

  @doc """
  Creates an invitation.
  """
  def create_invitation(attrs \\ %{}) do
    %Invitation{}
    |> Invitation.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Gets an invitation by token.
  """
  def get_invitation_by_token(token) do
    Invitation
    |> where([i], i.token == ^token)
    |> preload([:invited_by, :organization])
    |> Repo.one()
  end

  @doc """
  Accepts an invitation and creates a user account.
  """
  def accept_invitation(invitation, user_attrs) do
    if Invitation.pending?(invitation) do
      Repo.transaction(fn ->
        # Mark invitation as accepted
        accepted_at = DateTime.utc_now()

        invitation_changeset =
          Invitation.accept_changeset(invitation, %{accepted_at: accepted_at})

        with {:ok, _accepted_invitation} <- Repo.update(invitation_changeset),
             # Generate unique username based on preferred username
             preferred_username = Map.get(user_attrs, "username", "user"),
             unique_username =
               User.generate_unique_username(preferred_username, invitation.organization_id, Repo),
             user_attrs_with_org =
               user_attrs
               |> Map.put("organization_id", invitation.organization_id)
               |> Map.put("role", invitation.role)
               |> Map.put("username", unique_username)
               |> normalize_user_email_attrs(invitation.email,
                 default_type: "work",
                 default_primary: true,
                 verified_at: accepted_at
               ),
             {:ok, user} <- Authify.Accounts.create_user(user_attrs_with_org) do
          user
        else
          {:error, changeset} -> Repo.rollback(changeset)
        end
      end)
    else
      {:error, :invitation_invalid}
    end
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking invitation changes.
  """
  def change_invitation(%Invitation{} = invitation, attrs \\ %{}) do
    Invitation.changeset(invitation, attrs)
  end

  @doc """
  Lists invitations for an organization.
  """
  def list_invitations(organization_id) do
    from(i in Invitation,
      where: i.organization_id == ^organization_id,
      preload: [:invited_by, :organization],
      order_by: [desc: i.inserted_at]
    )
    |> Repo.all()
  end

  @doc """
  Returns the list of invitations sent by a specific user.
  """
  def list_invitations_by_inviter(inviter_id) do
    from(i in Invitation,
      where: i.invited_by_id == ^inviter_id,
      preload: [:invited_by, :organization],
      order_by: [desc: i.inserted_at]
    )
    |> Repo.all()
  end

  @doc """
  Gets a single invitation.
  """
  def get_invitation!(id), do: Repo.get!(Invitation, id)

  @doc """
  Updates an invitation.
  """
  def update_invitation(invitation, attrs) do
    invitation
    |> Invitation.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes an invitation.
  """
  def delete_invitation(invitation) do
    Repo.delete(invitation)
  end

  @doc """
  Lists pending invitations for an organization.
  """
  def list_pending_invitations(organization_id) do
    current_time = DateTime.utc_now()

    from(i in Invitation,
      where:
        i.organization_id == ^organization_id and is_nil(i.accepted_at) and
          i.expires_at > ^current_time,
      preload: [:invited_by, :organization],
      order_by: [desc: i.inserted_at]
    )
    |> Repo.all()
  end

  @doc """
  Creates an invitation and emits event to trigger email workflow.

  Emits an `invite_created` event that triggers the invitation workflow,
  which includes sending the invitation email asynchronously via the task system.

  Returns {:ok, invitation} on success or {:error, changeset} on validation failure.
  """
  def create_invitation_and_send_email(attrs, inviter) do
    attrs_with_inviter = Map.put(attrs, "invited_by_id", inviter.id)

    case create_invitation(attrs_with_inviter) do
      {:ok, invitation} ->
        # Preload associations for organization_id
        invitation = Repo.preload(invitation, [:organization, :invited_by])

        # Emit event to trigger invitation workflow (email sending)
        case Authify.Tasks.EventHandler.handle_event(:invite_created, %{
               invitation_id: invitation.id,
               organization_id: invitation.organization_id
             }) do
          {:ok, _task} ->
            require Logger
            Logger.info("Invitation workflow triggered for #{invitation.email}")

          {:error, reason} ->
            require Logger
            Logger.error("Failed to trigger invitation workflow: #{inspect(reason)}")
        end

        {:ok, invitation}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Builds the full URL for accepting an invitation.

  The invitation must have the organization association preloaded.
  """
  def build_invitation_accept_url(invitation) do
    organization = invitation.organization

    # Get the effective email link domain for this organization
    # (uses configured email_link_domain or falls back to default domain)
    domain = Authify.Organizations.get_email_link_domain(organization)

    # Build the accept URL (GET route that shows the acceptance form)
    "#{build_base_url(domain)}/invite/#{invitation.token}"
  end

  @doc """
  Cleans up expired invitations.
  """
  def cleanup_expired_invitations do
    cutoff_date = DateTime.add(DateTime.utc_now(), -30, :day)

    from(i in Invitation,
      where: i.expires_at < ^cutoff_date
    )
    |> Repo.delete_all()
    |> elem(0)
  end

  @doc """
  Cleans up expired invitations with organization parameter.
  """
  def cleanup_expired_invitations(organization_id) do
    current_time = DateTime.utc_now()

    from(i in Invitation,
      where: i.organization_id == ^organization_id and i.expires_at < ^current_time
    )
    |> Repo.delete_all()
  end

  @doc """
  Gets invitation stats.
  """
  def get_invitation_stats do
    total = from(i in Invitation) |> Repo.aggregate(:count, :id)
    pending = from(i in Invitation, where: is_nil(i.accepted_at)) |> Repo.aggregate(:count, :id)

    accepted =
      from(i in Invitation, where: not is_nil(i.accepted_at)) |> Repo.aggregate(:count, :id)

    acceptance_rate = if total > 0, do: accepted / total * 100, else: 0.0

    %{
      total_invitations: total,
      pending_invitations: pending,
      accepted_invitations: accepted,
      total: total,
      pending: pending,
      accepted: accepted,
      acceptance_rate: acceptance_rate
    }
  end

  @doc """
  Counts total invitations.
  """
  def count_invitations do
    from(i in Invitation) |> Repo.aggregate(:count, :id)
  end

  @doc """
  Counts expired invitations.
  """
  def count_expired_invitations do
    cutoff_date = DateTime.utc_now()

    from(i in Invitation, where: i.expires_at < ^cutoff_date)
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Counts expired invitations that are ready for cleanup (expired more than 48 hours ago).
  This matches the cleanup task's grace period logic.
  """
  def count_cleanable_invitations do
    cutoff = DateTime.utc_now() |> DateTime.add(-48, :hour)

    from(i in Invitation,
      where: is_nil(i.accepted_at),
      where: i.expires_at < ^cutoff
    )
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Counts invitations created since a given date.
  """
  def count_invitations_since(date) do
    from(i in Invitation,
      where: i.inserted_at >= ^date
    )
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Counts pending invitations.
  """
  def count_pending_invitations do
    from(i in Invitation, where: is_nil(i.accepted_at))
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Counts accepted invitations.
  """
  def count_accepted_invitations do
    from(i in Invitation, where: not is_nil(i.accepted_at))
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Counts invitations accepted since a given date.
  """
  def count_invitations_accepted_since(date) do
    from(i in Invitation,
      where: not is_nil(i.accepted_at) and i.accepted_at >= ^date
    )
    |> Repo.aggregate(:count, :id)
  end

  # Build the base URL with proper protocol and port for the environment
  defp build_base_url(domain) do
    if Application.get_env(:authify, :env) == :dev do
      "http://#{domain}:4000"
    else
      "https://#{domain}"
    end
  end

  # Normalize email attributes before creating a user from an invitation.
  defp normalize_user_email_attrs(attrs, fallback_email, opts) do
    default_type = Keyword.get(opts, :default_type, "work")
    default_primary = Keyword.get(opts, :default_primary, true)
    verified_at = Keyword.get(opts, :verified_at)

    {existing_emails, attrs_without_emails} = pop_email_entries(attrs)

    normalized_emails =
      existing_emails
      |> to_email_list()
      |> Enum.map(&normalize_email_entry(&1, default_type, verified_at))
      |> Enum.reject(&is_nil/1)

    normalized_emails =
      case normalized_emails do
        [] ->
          fallback_email
          |> build_email_from_value(
            type: default_type,
            primary: default_primary,
            verified_at: verified_at
          )
          |> List.wrap()

        emails ->
          emails
      end

    normalized_emails = ensure_primary_email(normalized_emails)

    attrs_without_emails
    |> drop_email_key()
    |> maybe_put_emails(normalized_emails)
  end

  defp pop_email_entries(attrs) do
    case Map.pop(attrs, "emails") do
      {nil, attrs_without_string_key} ->
        case Map.pop(attrs_without_string_key, :emails) do
          {nil, attrs_without_atom_key} -> {nil, attrs_without_atom_key}
          {emails, attrs_without_atom_key} -> {emails, attrs_without_atom_key}
        end

      {emails, attrs_without_string_key} ->
        {emails, attrs_without_string_key}
    end
  end

  defp drop_email_key(attrs) do
    attrs
    |> Map.delete("email")
    |> Map.delete(:email)
  end

  defp maybe_put_emails(attrs, []), do: attrs
  defp maybe_put_emails(attrs, emails), do: Map.put(attrs, "emails", emails)

  defp to_email_list(nil), do: []

  defp to_email_list(emails) when is_list(emails) do
    emails
  end

  defp to_email_list(emails) when is_map(emails) do
    emails
    |> Enum.sort_by(fn {key, _} -> to_string(key) end)
    |> Enum.map(fn {_key, value} -> value end)
  end

  defp to_email_list(_), do: []

  defp normalize_email_entry(email, default_type, verified_at) when is_map(email) do
    email = stringify_keys(email)

    case normalize_email_value(Map.get(email, "value")) do
      nil ->
        nil

      value ->
        %{}
        |> Map.put("value", value)
        |> Map.put("type", Map.get(email, "type") || default_type)
        |> Map.put("primary", normalize_primary_flag(Map.get(email, "primary")))
        |> maybe_put_non_nil("display", blank_to_nil(Map.get(email, "display")))
        |> maybe_put_non_nil("verified_at", Map.get(email, "verified_at") || verified_at)
    end
  end

  defp normalize_email_entry(value, default_type, verified_at) when is_binary(value) do
    build_email_from_value(value, type: default_type, primary: false, verified_at: verified_at)
  end

  defp normalize_email_entry(_, _, _), do: nil

  defp build_email_from_value(value, opts) do
    case normalize_email_value(value) do
      nil ->
        nil

      normalized ->
        %{}
        |> Map.put("value", normalized)
        |> Map.put("type", Keyword.get(opts, :type, "work"))
        |> Map.put("primary", Keyword.get(opts, :primary, true))
        |> maybe_put_non_nil("verified_at", Keyword.get(opts, :verified_at))
    end
  end

  defp normalize_email_value(nil), do: nil

  defp normalize_email_value(value) when is_binary(value) do
    value = String.trim(value)

    if value == "" do
      nil
    else
      value
    end
  end

  defp normalize_email_value(value) when is_atom(value),
    do: value |> Atom.to_string() |> normalize_email_value()

  defp normalize_email_value(_), do: nil

  defp normalize_primary_flag(value) when value in [true, "true", "1", 1], do: true
  defp normalize_primary_flag(_), do: false

  defp ensure_primary_email([]), do: []

  defp ensure_primary_email(emails) do
    primary_index =
      emails
      |> Enum.find_index(fn email -> Map.get(email, "primary") == true end)
      |> case do
        nil -> 0
        index -> index
      end

    emails
    |> Enum.with_index()
    |> Enum.map(fn {email, index} ->
      Map.put(email, "primary", index == primary_index)
    end)
  end

  defp stringify_keys(map) do
    map
    |> Enum.map(fn
      {key, value} when is_atom(key) -> {Atom.to_string(key), value}
      {key, value} when is_binary(key) -> {key, value}
      {key, value} -> {to_string(key), value}
    end)
    |> Enum.into(%{})
  end

  defp blank_to_nil(nil), do: nil

  defp blank_to_nil(value) when is_binary(value) do
    value = String.trim(value)
    if value == "", do: nil, else: value
  end

  defp blank_to_nil(value), do: value

  defp maybe_put_non_nil(map, _key, nil), do: map
  defp maybe_put_non_nil(map, key, value), do: Map.put(map, key, value)
end
