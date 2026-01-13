defmodule Authify.Accounts do
  @moduledoc """
  Simplified Accounts context for single organization model.
  """

  import Ecto.Query, warn: false
  import Ecto.Changeset, only: [get_change: 2, get_field: 2]
  alias Authify.Repo

  alias Authify.Accounts.{
    Certificate,
    Group,
    GroupApplication,
    GroupMembership,
    Invitation,
    Organization,
    PersonalAccessToken,
    User
  }

  ## Organizations

  @doc """
  Returns the list of organizations.
  """
  def list_organizations do
    Repo.all(Organization)
  end

  @doc """
  Returns a filtered and sorted list of organizations.

  ## Options
    * `:sort` - Field to sort by (atom, e.g., :name, :slug, :inserted_at)
    * `:order` - Sort order (:asc or :desc, defaults to :asc)
    * `:search` - Text search across name and slug fields
    * `:status` - Filter by active status (boolean or "all")

  ## Examples

      iex> list_organizations_filtered(sort: :name, order: :desc, search: "acme")
      [%Organization{}, ...]
  """
  def list_organizations_filtered(opts \\ []) do
    query = from(o in Organization)

    query
    |> apply_organization_filters(opts)
    |> apply_organization_search(opts[:search])
    |> apply_organization_sorting(opts[:sort], opts[:order])
    |> Repo.all()
  end

  defp apply_organization_filters(query, opts) do
    maybe_filter_organization_by_status(query, opts[:status])
  end

  defp maybe_filter_organization_by_status(query, nil),
    do: where(query, [o], o.active == true)

  defp maybe_filter_organization_by_status(query, ""),
    do: where(query, [o], o.active == true)

  defp maybe_filter_organization_by_status(query, "all"), do: query
  defp maybe_filter_organization_by_status(query, true), do: where(query, [o], o.active == true)

  defp maybe_filter_organization_by_status(query, "true"),
    do: where(query, [o], o.active == true)

  defp maybe_filter_organization_by_status(query, false),
    do: where(query, [o], o.active == false)

  defp maybe_filter_organization_by_status(query, "false"),
    do: where(query, [o], o.active == false)

  defp maybe_filter_organization_by_status(query, _), do: where(query, [o], o.active == true)

  defp apply_organization_search(query, nil), do: query
  defp apply_organization_search(query, ""), do: query

  defp apply_organization_search(query, search_term) when is_binary(search_term) do
    search_pattern = "%#{search_term}%"

    where(
      query,
      [o],
      like(o.name, ^search_pattern) or like(o.slug, ^search_pattern)
    )
  end

  defp apply_organization_sorting(query, nil, _), do: order_by(query, [o], asc: o.name)
  defp apply_organization_sorting(query, "", _), do: order_by(query, [o], asc: o.name)

  defp apply_organization_sorting(query, sort_field, order)
       when sort_field in [:name, :slug, :inserted_at, :updated_at] do
    order_atom = if order == :desc or order == "desc", do: :desc, else: :asc
    order_by(query, [o], ^[{order_atom, sort_field}])
  end

  defp apply_organization_sorting(query, _sort_field, _order),
    do: order_by(query, [o], asc: o.name)

  @doc """
  Gets a single organization.
  """
  def get_organization!(id), do: Repo.get!(Organization, id)

  @doc """
  Gets a single organization (returns nil if not found).
  """
  def get_organization(id), do: Repo.get(Organization, id)

  @doc """
  Gets an organization by slug.
  """
  def get_organization_by_slug(slug) when is_binary(slug) do
    Repo.get_by(Organization, slug: slug)
  end

  @doc """
  Creates an organization.
  """
  def create_organization(attrs \\ %{}) do
    %Organization{}
    |> Organization.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates an organization.
  """
  def update_organization(%Organization{} = organization, attrs) do
    organization
    |> Organization.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes an organization.
  """
  def delete_organization(%Organization{} = organization) do
    Repo.delete(organization)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking organization changes.
  """
  def change_organization(%Organization{} = organization, attrs \\ %{}) do
    Organization.changeset(organization, attrs)
  end

  ## Users

  @doc """
  Returns the list of users for a given organization.
  """
  def list_users(organization_id) do
    from(u in User,
      where: u.organization_id == ^organization_id and u.active == true,
      preload: [:organization]
    )
    |> Repo.all()
  end

  @doc """
  Returns a filtered and sorted list of users for a given organization.

  ## Options
    * `:sort` - Field to sort by (atom, e.g., :name, :email, :inserted_at)
    * `:order` - Sort order (:asc or :desc, defaults to :asc)
    * `:search` - Text search across name and email fields
    * `:role` - Filter by role ("admin" or "user")
    * `:status` - Filter by active status (boolean or "all")

  ## Examples

      iex> list_users_filtered(org_id, sort: :email, order: :desc, search: "john")
      [%User{}, ...]
  """
  def list_users_filtered(organization_id, opts \\ []) do
    query =
      from(u in User,
        where: u.organization_id == ^organization_id,
        preload: [:organization]
      )

    query
    |> apply_user_filters(opts)
    |> apply_user_search(opts[:search])
    |> apply_user_sorting(opts[:sort], opts[:order])
    |> Repo.all()
  end

  defp apply_user_filters(query, opts) do
    query
    |> maybe_filter_by_role(opts[:role])
    |> maybe_filter_by_status(opts[:status])
  end

  defp maybe_filter_by_role(query, nil), do: query
  defp maybe_filter_by_role(query, ""), do: query

  defp maybe_filter_by_role(query, role) when role in ["admin", "user"] do
    where(query, [u], u.role == ^role)
  end

  defp maybe_filter_by_role(query, _), do: query

  defp maybe_filter_by_status(query, nil), do: where(query, [u], u.active == true)
  defp maybe_filter_by_status(query, ""), do: where(query, [u], u.active == true)
  defp maybe_filter_by_status(query, "all"), do: query
  defp maybe_filter_by_status(query, true), do: where(query, [u], u.active == true)
  defp maybe_filter_by_status(query, "true"), do: where(query, [u], u.active == true)
  defp maybe_filter_by_status(query, false), do: where(query, [u], u.active == false)
  defp maybe_filter_by_status(query, "false"), do: where(query, [u], u.active == false)
  defp maybe_filter_by_status(query, _), do: where(query, [u], u.active == true)

  defp apply_user_search(query, nil), do: query
  defp apply_user_search(query, ""), do: query

  defp apply_user_search(query, search_term) when is_binary(search_term) do
    search_pattern = "%#{search_term}%"

    where(
      query,
      [u],
      like(u.email, ^search_pattern) or
        like(fragment("CONCAT(?, ' ', ?)", u.first_name, u.last_name), ^search_pattern)
    )
  end

  defp apply_user_sorting(query, nil, _), do: order_by(query, [u], asc: u.email)
  defp apply_user_sorting(query, "", _), do: order_by(query, [u], asc: u.email)

  defp apply_user_sorting(query, sort_field, order)
       when sort_field in [:email, :first_name, :last_name, :role, :inserted_at] do
    order_atom = if order == :desc or order == "desc", do: :desc, else: :asc
    order_by(query, [u], ^[{order_atom, sort_field}])
  end

  defp apply_user_sorting(query, _sort_field, _order), do: order_by(query, [u], asc: u.email)

  @doc """
  Gets a single user.
  """
  def get_user!(id) do
    from(u in User,
      where: u.id == ^id,
      preload: [:organization]
    )
    |> Repo.one!()
  end

  @doc """
  Gets a user by id.
  """
  def get_user(id) when is_binary(id) do
    case Integer.parse(id) do
      {int_id, ""} -> get_user(int_id)
      _ -> nil
    end
  end

  def get_user(id) when is_integer(id) do
    from(u in User,
      where: u.id == ^id,
      preload: [:organization]
    )
    |> Repo.one()
  end

  @doc """
  Gets a user by email and organization.
  """
  def get_user_by_email_and_organization(email, organization_id) do
    from(u in User,
      where: u.email == ^email and u.organization_id == ^organization_id and u.active == true,
      preload: [:organization]
    )
    |> Repo.one()
  end

  @doc """
  Creates a user.
  """
  def create_user(attrs \\ %{}) do
    %User{}
    |> User.registration_changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Creates an organization with an admin user.
  """
  def create_organization_with_admin(org_attrs, user_attrs) do
    Repo.transaction(fn ->
      with {:ok, organization} <- create_organization(org_attrs),
           # Generate unique username based on preferred username
           preferred_username = Map.get(user_attrs, "username", "admin"),
           unique_username =
             User.generate_unique_username(preferred_username, organization.id, Repo),
           user_attrs_with_org =
             user_attrs
             |> Map.put("organization_id", organization.id)
             |> Map.put("role", "admin")
             |> Map.put("username", unique_username),
           {:ok, user} <- create_user(user_attrs_with_org) do
        {organization, user}
      else
        {:error, changeset} -> Repo.rollback(changeset)
      end
    end)
  end

  @doc """
  Updates a user.
  """
  def update_user(%User{} = user, attrs) do
    changeset = User.changeset(user, attrs)

    # If email is being changed, clear email verification
    changeset =
      if Ecto.Changeset.get_change(changeset, :email) do
        Ecto.Changeset.put_change(changeset, :email_confirmed_at, nil)
      else
        changeset
      end

    Repo.update(changeset)
  end

  @doc """
  Deletes a user.
  """
  def delete_user(%User{} = user) do
    Repo.delete(user)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking user changes.
  """
  def change_user(%User{} = user, attrs \\ %{}) do
    User.changeset(user, attrs)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for user registration.
  """
  def change_user_registration(%User{} = user, attrs \\ %{}) do
    User.registration_changeset(user, attrs)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for user forms without validations.
  This is used for initial form rendering to avoid showing validation errors
  before the user has attempted to submit the form.
  """
  def change_user_form(%User{} = user, attrs \\ %{}) do
    user
    |> Ecto.Changeset.cast(attrs, [
      :email,
      :first_name,
      :last_name,
      :username,
      :password,
      :password_confirmation
    ])
  end

  @doc """
  Updates a user's profile information (name, email, username).
  """
  def update_user_profile(%User{} = user, attrs) do
    changeset = User.changeset(user, attrs)

    # If email is being changed, clear email verification
    changeset =
      if Ecto.Changeset.get_change(changeset, :email) do
        Ecto.Changeset.put_change(changeset, :email_confirmed_at, nil)
      else
        changeset
      end

    Repo.update(changeset)
  end

  @doc """
  Returns the total count of users across all organizations.
  """
  def count_users do
    from(u in User, where: u.active == true)
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Returns the count of users in a specific organization.
  """
  def count_users(organization_id) do
    from(u in User,
      where: u.organization_id == ^organization_id and u.active == true
    )
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Gets a user by id with organization preloaded (alias for compatibility).
  """
  def get_user_with_organizations!(id) do
    get_user!(id)
  end

  @doc """
  Gets a user by id with organization preloaded (alias for compatibility).
  """
  def get_user_with_organizations(id) do
    get_user(id)
  end

  @doc """
  Gets a user from any organization (global lookup).
  """
  def get_user_globally!(id) do
    from(u in User,
      where: u.id == ^id,
      preload: [:organization]
    )
    |> Repo.one!()
  end

  @doc """
  Gets a user from any organization (global lookup).
  """
  def get_user_globally(id) do
    from(u in User,
      where: u.id == ^id,
      preload: [:organization]
    )
    |> Repo.one()
  end

  @doc """
  Lists all global administrators.
  """
  def list_global_admins do
    global_org = get_global_organization()

    if global_org do
      list_users(global_org.id)
    else
      []
    end
  end

  @doc """
  Creates a user with a specific role in an organization.
  """
  def create_user_with_role(user_attrs, organization_id, role) do
    # Generate unique username based on preferred username
    preferred_username = Map.get(user_attrs, "username", "user")
    unique_username = User.generate_unique_username(preferred_username, organization_id, Repo)

    user_attrs_with_org =
      user_attrs
      |> Map.put("organization_id", organization_id)
      |> Map.put("role", role)
      |> Map.put("username", unique_username)

    create_user(user_attrs_with_org)
  end

  @doc """
  Creates a user with default role in an organization.
  """
  def create_user_with_role(user_attrs, organization_id) do
    create_user_with_role(user_attrs, organization_id, "user")
  end

  @doc """
  Creates a user and sends email verification.

  This should be used when creating users directly (not through invitation).
  Users created through invitations have already verified their email.
  """
  def create_user_and_send_verification(user_attrs, organization_id, role \\ "user") do
    case create_user_with_role(user_attrs, organization_id, role) do
      {:ok, user} ->
        # Preload organization for email
        user = Repo.preload(user, :organization)

        # Generate verification token
        case generate_email_verification_token(user) do
          {:ok, updated_user, plaintext_token} ->
            # Build the verification URL
            verification_url = build_email_verification_url(user.organization, plaintext_token)

            # Send verification email
            case Authify.Email.send_email_verification_email(updated_user, verification_url) do
              {:ok, _metadata} ->
                require Logger
                Logger.info("Email verification sent to #{user.email}")

              {:error, :smtp_not_configured} ->
                require Logger

                Logger.warning(
                  "SMTP not configured for organization #{user.organization.slug}, user created but verification email not sent"
                )

              {:error, reason} ->
                require Logger
                Logger.error("Failed to send verification email: #{inspect(reason)}")
            end

            {:ok, updated_user}

          {:error, changeset} ->
            {:error, changeset}
        end

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Builds the full URL for email verification.
  """
  def build_email_verification_url(organization, token) do
    # Get the effective email link domain for this organization
    # (uses configured email_link_domain or falls back to default domain)
    domain = Authify.Organizations.get_email_link_domain(organization)

    # Build the verification URL
    "#{build_base_url(domain)}/email/verify/#{token}"
  end

  # Build the base URL with proper protocol and port for the environment
  defp build_base_url(domain) do
    if Application.get_env(:authify, :env) == :dev do
      # In development, use HTTP and port 4000
      "http://#{domain}:4000"
    else
      # In production/test, use HTTPS without explicit port
      "https://#{domain}"
    end
  end

  @doc """
  Updates a user's role within their organization.
  """
  def update_user_role(user, new_role) do
    update_user(user, %{"role" => new_role})
  end

  @doc """
  Forces a password reset for a user.
  """
  def force_password_reset(user) do
    # For now, we'll update the user to require a password change
    # In a real implementation, you might want to generate a reset token
    update_user(user, %{"password_reset_required" => true})
  end

  @doc """
  Disables a user account.
  """
  def disable_user(user) do
    update_user(user, %{"active" => false})
  end

  @doc """
  Enables a user account.
  """
  def enable_user(user) do
    update_user(user, %{"active" => true})
  end

  @doc """
  Removes a user from an organization.
  Since we moved to single organization model, this disables the user.
  """
  def remove_user_from_organization(user_id, _organization_id) do
    user = get_user!(user_id)

    case disable_user(user) do
      {:ok, _user} -> :ok
      {:error, changeset} -> {:error, changeset}
    end
  end

  ## Authentication

  @doc """
  Authenticates a user with email and password within an organization.
  """
  def authenticate_user(email, password, organization_id) do
    user = get_user_by_email_and_organization(email, organization_id)

    cond do
      user && User.valid_password?(user, password) -> {:ok, user}
      user -> {:error, :invalid_password}
      true -> {:error, :user_not_found}
    end
  end

  ## Global Admin Functions

  @doc """
  Returns the global organization.
  """
  def get_global_organization do
    Repo.get_by(Organization, slug: "authify-global")
  end

  @doc """
  Gets the global organization, raising if not found.
  """
  def get_global_organization! do
    Repo.get_by!(Organization, slug: "authify-global")
  end

  @doc """
  Checks if a user is a global admin.
  """
  def global_admin?(%User{} = user) do
    User.global_admin?(user)
  end

  ## Invitations

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
               |> Map.put("email", invitation.email)
               |> Map.put("organization_id", invitation.organization_id)
               |> Map.put("role", invitation.role)
               |> Map.put("username", unique_username)
               # Email is verified since they clicked the link we sent to that email
               |> Map.put("email_confirmed_at", accepted_at),
             {:ok, user} <- create_user(user_attrs_with_org) do
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
  Creates an invitation and sends email.

  Sends the invitation email using Swoosh.deliver/2 (non-blocking in Elixir).
  If email sending fails (e.g., SMTP not configured), the invitation is still
  created successfully but a warning is logged.

  Returns {:ok, invitation} on success or {:error, changeset} on validation failure.
  """
  def create_invitation_and_send_email(attrs, inviter) do
    attrs_with_inviter = Map.put(attrs, "invited_by_id", inviter.id)

    case create_invitation(attrs_with_inviter) do
      {:ok, invitation} ->
        # Preload associations needed for email
        invitation = Repo.preload(invitation, [:organization, :invited_by])

        # Build the accept URL using the organization's email link domain
        accept_url = build_invitation_accept_url(invitation)

        # Send email asynchronously (fire and forget)
        case Authify.Email.send_invitation_email(invitation, accept_url) do
          {:ok, _metadata} ->
            require Logger
            Logger.info("Invitation email sent to #{invitation.email}")

          {:error, :smtp_not_configured} ->
            require Logger

            Logger.warning(
              "SMTP not configured for organization #{invitation.organization.slug}, invitation created but email not sent"
            )

          {:error, reason} ->
            require Logger
            Logger.error("Failed to send invitation email: #{inspect(reason)}")
        end

        {:ok, invitation}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  # Build the full URL for accepting an invitation
  defp build_invitation_accept_url(invitation) do
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

  ## Certificates

  @doc """
  Returns the list of certificates for an organization.
  """
  def list_certificates(%Organization{id: org_id}) do
    from(c in Certificate,
      where: c.organization_id == ^org_id,
      order_by: [desc: c.inserted_at]
    )
    |> Repo.all()
  end

  @doc """
  Gets a single certificate.
  """
  def get_certificate!(id), do: Repo.get!(Certificate, id)

  @doc """
  Creates a certificate.
  """
  def create_certificate(%Organization{} = organization, attrs \\ %{}) do
    attrs = Map.put(attrs, "organization_id", organization.id)

    changeset =
      %Certificate{}
      |> Certificate.changeset(attrs)

    # If creating an active certificate, deactivate existing active certificates of same usage
    if get_change(changeset, :is_active) == true do
      usage = get_field(changeset, :usage)
      deactivate_existing_active_certificates(organization.id, usage)
    end

    Repo.insert(changeset)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking certificate changes.
  """
  def change_certificate(%Certificate{} = certificate, attrs \\ %{}) do
    Certificate.changeset(certificate, attrs)
  end

  @doc """
  Generates a self-signed certificate with specified usage.
  """
  def generate_certificate(%Organization{} = organization, attrs \\ %{}) do
    usage = Map.get(attrs, "usage", "saml_signing")

    # Create self-signed certificate
    validity_days = Map.get(attrs, "validity_days", 365)

    # Create subject based on usage type
    usage_label =
      case usage do
        "saml_signing" -> "SAML Signing"
        "saml_encryption" -> "SAML Encryption"
        "oauth_signing" -> "OAuth Signing"
        _ -> "Certificate"
      end

    subject = "/CN=#{organization.name} #{usage_label}/O=#{organization.name}"

    {private_key_pem, certificate_pem} =
      create_self_signed_certificate(nil, subject, validity_days)

    # Default certificate name based on usage
    default_name =
      case usage do
        "saml_signing" -> "SAML Signing Certificate"
        "saml_encryption" -> "SAML Encryption Certificate"
        "oauth_signing" -> "OAuth Signing Certificate"
        _ -> "Certificate"
      end

    # Note: private_key is automatically encrypted by Authify.Encrypted.Binary Ecto type
    certificate_attrs = %{
      "name" => Map.get(attrs, "name", default_name),
      "usage" => usage,
      "private_key" => private_key_pem,
      "certificate" => certificate_pem,
      "expires_at" => DateTime.add(DateTime.utc_now(), validity_days, :day),
      "is_active" => Map.get(attrs, "is_active", false)
    }

    create_certificate(organization, certificate_attrs)
  end

  @doc """
  Generates a SAML signing certificate (alias for compatibility).
  """
  def generate_saml_signing_certificate(organization, attrs \\ %{}) do
    attrs = Map.put(attrs, "usage", "saml_signing")
    generate_certificate(organization, attrs)
  end

  @doc """
  Gets a certificate with organization verification.
  """
  def get_certificate!(id, organization) do
    certificate = get_certificate!(id)

    if certificate.organization_id == organization.id do
      certificate
    else
      raise Ecto.NoResultsError, queryable: Certificate
    end
  end

  @doc """
  Gets a certificate's private key.

  The private key is automatically decrypted by the Authify.Encrypted.Binary Ecto type,
  so this function simply returns it wrapped in {:ok, ...} for API compatibility.

  Returns `{:ok, private_key}` on success.
  """
  def decrypt_certificate_private_key(%Certificate{private_key: private_key}) do
    {:ok, private_key}
  end

  @doc """
  Updates a certificate.
  """
  def update_certificate(certificate, attrs) do
    changeset =
      certificate
      |> Certificate.changeset(attrs)

    # If updating to active, deactivate existing active certificates of same usage
    if get_change(changeset, :is_active) == true do
      usage = get_field(changeset, :usage)
      organization_id = get_field(changeset, :organization_id)
      deactivate_existing_active_certificates(organization_id, usage, certificate.id)
    end

    Repo.update(changeset)
  end

  @doc """
  Deletes a certificate.
  """
  def delete_certificate(certificate) do
    Repo.delete(certificate)
  end

  @doc """
  Gets the active SAML signing certificate for an organization.
  """
  def get_active_saml_signing_certificate(organization) do
    from(c in Certificate,
      where:
        c.organization_id == ^organization.id and c.usage == "saml_signing" and
          c.is_active == true,
      limit: 1
    )
    |> Repo.one()
  end

  defp create_self_signed_certificate(_private_key, subject, validity_days) do
    # Generate RSA private key using X509 library
    private_key = X509.PrivateKey.new_rsa(2048)

    # Create self-signed certificate
    certificate =
      X509.Certificate.self_signed(
        private_key,
        subject,
        validity: validity_days
      )

    # Convert to PEM format
    private_key_pem = X509.PrivateKey.to_pem(private_key)
    certificate_pem = X509.Certificate.to_pem(certificate)

    {String.trim(private_key_pem), String.trim(certificate_pem)}
  rescue
    error ->
      # Fallback to placeholder if certificate generation fails
      private_key_pem = """
      -----BEGIN RSA PRIVATE KEY-----
      PLACEHOLDER_PRIVATE_KEY_DATA_ERROR_#{inspect(error)}
      -----END RSA PRIVATE KEY-----
      """

      certificate_pem = """
      -----BEGIN CERTIFICATE-----
      PLACEHOLDER_CERTIFICATE_DATA_ERROR_#{inspect(error)}
      -----END CERTIFICATE-----
      """

      {String.trim(private_key_pem), String.trim(certificate_pem)}
  end

  ## Personal Access Tokens

  @doc """
  Creates a personal access token for a user.
  """
  def create_personal_access_token(user, organization, attrs) do
    %PersonalAccessToken{}
    |> PersonalAccessToken.changeset(
      attrs
      |> Map.put("user_id", user.id)
      |> Map.put("organization_id", organization.id)
    )
    |> Repo.insert()
  end

  @doc """
  Lists personal access tokens for a user.
  """
  def list_personal_access_tokens(user) do
    from(p in PersonalAccessToken,
      where: p.user_id == ^user.id,
      order_by: [desc: p.inserted_at]
    )
    |> Repo.all()
    |> Repo.preload(:scopes)
  end

  @doc """
  Gets a personal access token for a user.
  """
  def get_personal_access_token!(id, user) do
    from(p in PersonalAccessToken,
      where: p.id == ^id and p.user_id == ^user.id
    )
    |> Repo.one!()
  end

  @doc """
  Deletes a personal access token.
  """
  def delete_personal_access_token(token) do
    Repo.delete(token)
  end

  @doc """
  Changes a personal access token.
  """
  def change_personal_access_token(token, attrs \\ %{}) do
    PersonalAccessToken.changeset(token, attrs)
  end

  @doc """
  Authenticates a personal access token.

  Hashes the provided token and verifies it against stored hashes in the database.
  """
  def authenticate_personal_access_token(token_string) do
    case String.split(token_string, "_", parts: 3) do
      ["authify", "pat", _token] ->
        # Hash the incoming token
        token_hash = PersonalAccessToken.hash_token(token_string)

        # Query for the token by hash
        from(p in PersonalAccessToken,
          where:
            p.token == ^token_hash and
              p.is_active == true and
              (is_nil(p.expires_at) or p.expires_at > ^DateTime.utc_now()),
          preload: [:user, :organization, :scopes]
        )
        |> Repo.one()
        |> case do
          nil ->
            {:error, :invalid_token}

          token ->
            # Update last_used_at
            update_token_last_used(token)
            {:ok, token}
        end

      _ ->
        {:error, :invalid_token}
    end
  end

  defp update_token_last_used(token) do
    token
    |> Ecto.Changeset.change(last_used_at: DateTime.utc_now() |> DateTime.truncate(:second))
    |> Repo.update()
  end

  ## Missing compatibility functions

  @doc """
  Gets a user within an organization (compatibility function).
  """
  def get_user_in_organization(id, organization_id) do
    case get_user(id) do
      nil ->
        nil

      user ->
        if user.organization_id == organization_id do
          user
        else
          nil
        end
    end
  end

  @doc """
  Lists users with pagination support.
  """
  def list_users(organization_id, opts) do
    page = Keyword.get(opts, :page, 1)
    per_page = Keyword.get(opts, :per_page, 25)
    offset = (page - 1) * per_page

    from(u in User,
      where: u.organization_id == ^organization_id and u.active == true,
      preload: [:organization],
      limit: ^per_page,
      offset: ^offset
    )
    |> Repo.all()
  end

  @doc """
  Gets user accessible applications through their groups.
  """
  def get_user_accessible_applications(%User{} = user, %Organization{} = organization) do
    # Get all groups that the user belongs to
    user_group_ids =
      from(gm in GroupMembership,
        where: gm.user_id == ^user.id,
        select: gm.group_id
      )
      |> Repo.all()

    if Enum.empty?(user_group_ids) do
      %{
        oauth2_applications: [],
        saml_service_providers: []
      }
    else
      # Get all application members for those groups
      application_members =
        from(ga in GroupApplication,
          where: ga.group_id in ^user_group_ids,
          select: {ga.application_id, ga.application_type}
        )
        |> Repo.all()

      # Separate OAuth and SAML application IDs
      {oauth_ids, saml_ids} =
        Enum.reduce(application_members, {[], []}, fn
          {app_id, "oauth2"}, {oauth_acc, saml_acc} -> {[app_id | oauth_acc], saml_acc}
          {app_id, "saml"}, {oauth_acc, saml_acc} -> {oauth_acc, [app_id | saml_acc]}
          _, acc -> acc
        end)

      # Fetch OAuth applications
      oauth2_applications =
        if Enum.empty?(oauth_ids) do
          []
        else
          alias Authify.OAuth.Application

          from(app in Application,
            where:
              app.id in ^oauth_ids and app.organization_id == ^organization.id and
                app.is_active == true
          )
          |> Repo.all()
        end

      # Fetch SAML service providers
      saml_service_providers =
        if Enum.empty?(saml_ids) do
          []
        else
          alias Authify.SAML.ServiceProvider

          from(sp in ServiceProvider,
            where:
              sp.id in ^saml_ids and sp.organization_id == ^organization.id and
                sp.is_active == true
          )
          |> Repo.all()
        end

      %{
        oauth2_applications: oauth2_applications,
        saml_service_providers: saml_service_providers
      }
    end
  end

  @doc """
  Gets user by email globally.
  """
  def get_user_by_email(email) do
    from(u in User,
      where: u.email == ^email and u.active == true,
      preload: [:organization]
    )
    |> Repo.one()
  end

  @doc """
  Creates a super admin user (placeholder).
  """
  def create_super_admin(attrs) do
    # For now, create a regular admin user in global organization
    global_org = get_global_organization()

    if global_org do
      create_user_with_role(attrs, global_org.id, "admin")
    else
      {:error, :no_global_organization}
    end
  end

  @doc """
  Change user password changeset.
  """
  def change_user_password(user) do
    User.password_changeset(user, %{})
  end

  @doc """
  Updates user password.
  """
  def update_user_password(user, attrs) do
    user
    |> User.password_changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Generates password reset token.
  """
  def generate_password_reset_token(user) do
    changeset = User.password_reset_changeset(user)

    case Repo.update(changeset) do
      {:ok, updated_user} ->
        # Return the plaintext token (virtual field) instead of the hash
        {:ok, updated_user, updated_user.plaintext_reset_token}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Gets user by password reset token.
  Hashes the provided token and looks up by hash.
  """
  def get_user_by_password_reset_token(nil), do: nil

  def get_user_by_password_reset_token(token) do
    token_hash = User.hash_password_reset_token(token)

    from(u in User,
      where:
        u.password_reset_token == ^token_hash and
          u.password_reset_expires_at > ^DateTime.utc_now(),
      preload: [:organization]
    )
    |> Repo.one()
  end

  @doc """
  Gets user by password reset token regardless of expiration.
  Useful for auditing scenarios where we need the user even if the token expired.
  """
  def get_user_by_password_reset_token_including_expired(nil), do: nil

  def get_user_by_password_reset_token_including_expired(token) do
    token_hash = User.hash_password_reset_token(token)

    from(u in User,
      where: u.password_reset_token == ^token_hash,
      preload: [:organization]
    )
    |> Repo.one()
  end

  @doc """
  Resets password with token.
  Hashes the provided token and looks up by hash.
  """
  def reset_password_with_token(token, password_params) do
    case get_user_by_password_reset_token_including_expired(token) do
      nil ->
        {:error, :token_not_found}

      user ->
        # Check if token is expired
        if user.password_reset_expires_at &&
             DateTime.compare(user.password_reset_expires_at, DateTime.utc_now()) == :lt do
          {:error, :token_expired}
        else
          changeset = User.password_reset_completion_changeset(user, password_params)

          case Repo.update(changeset) do
            {:ok, updated_user} -> {:ok, updated_user}
            {:error, changeset} -> {:error, changeset}
          end
        end
    end
  end

  @doc """
  Cleanup expired password reset tokens.
  """
  def cleanup_expired_password_reset_tokens do
    from(u in User,
      where:
        not is_nil(u.password_reset_token) and u.password_reset_expires_at < ^DateTime.utc_now()
    )
    |> Repo.update_all(set: [password_reset_token: nil, password_reset_expires_at: nil])
  end

  @doc """
  Generates email verification token.
  """
  def generate_email_verification_token(user) do
    changeset = User.email_verification_changeset(user)

    case Repo.update(changeset) do
      {:ok, updated_user} ->
        # Return the plaintext token (virtual field) instead of the hash
        {:ok, updated_user, updated_user.plaintext_verification_token}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Gets user by email verification token.
  Hashes the provided token and looks up by hash.
  """
  def get_user_by_email_verification_token(nil), do: nil

  def get_user_by_email_verification_token(token) do
    token_hash = User.hash_email_verification_token(token)

    from(u in User,
      where:
        u.email_verification_token == ^token_hash and
          u.email_verification_expires_at > ^DateTime.utc_now(),
      preload: [:organization]
    )
    |> Repo.one()
  end

  @doc """
  Verifies email with token.
  Hashes the provided token and looks up by hash.
  """
  def verify_email_with_token(token) do
    # Hash the incoming token to look up in database
    token_hash = User.hash_email_verification_token(token)

    # First check if user exists with this token (regardless of expiration)
    user_with_token =
      from(u in User,
        where: u.email_verification_token == ^token_hash,
        preload: [:organization]
      )
      |> Repo.one()

    case user_with_token do
      nil ->
        {:error, :token_not_found}

      user ->
        # Check if token is expired
        if user.email_verification_expires_at &&
             DateTime.compare(user.email_verification_expires_at, DateTime.utc_now()) == :lt do
          {:error, :token_expired}
        else
          changeset = User.email_verification_completion_changeset(user)

          case Repo.update(changeset) do
            {:ok, updated_user} -> {:ok, updated_user}
            {:error, changeset} -> {:error, changeset}
          end
        end
    end
  end

  @doc """
  Cleanup expired email verification tokens.
  """
  def cleanup_expired_email_verification_tokens do
    from(u in User,
      where:
        not is_nil(u.email_verification_token) and
          u.email_verification_expires_at < ^DateTime.utc_now()
    )
    |> Repo.update_all(set: [email_verification_token: nil, email_verification_expires_at: nil])
  end

  @doc """
  Change user password with 2 params.
  """
  def change_user_password(user, attrs) do
    User.password_changeset(user, attrs)
  end

  @doc """
  Update invitation.
  """
  def update_invitation(invitation, attrs) do
    invitation
    |> Invitation.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Gets user organization record (compatibility).
  """
  def get_user_organization(user_id, organization_id) do
    user = get_user(user_id)

    if user && user.organization_id == organization_id do
      # Return a simple struct that mimics the old UserOrganization
      %{
        user_id: user_id,
        organization_id: organization_id,
        role: user.role,
        active: user.active,
        # Use user's creation time as joined_at
        joined_at: user.inserted_at
      }
    else
      nil
    end
  end

  @doc """
  Lists organizations with stats.
  """
  def list_organizations_with_stats do
    from(o in Organization,
      left_join: u in User,
      on: u.organization_id == o.id and u.active == true,
      group_by: o.id,
      select: %{
        id: o.id,
        name: o.name,
        slug: o.slug,
        active: o.active,
        user_count: count(u.id),
        inserted_at: o.inserted_at,
        updated_at: o.updated_at
      },
      order_by: [desc: o.inserted_at]
    )
    |> Repo.all()
  end

  @doc """
  Returns a filtered and sorted list of organizations with stats.

  ## Options
    * `:sort` - Field to sort by (atom, e.g., :name, :slug, :inserted_at)
    * `:order` - Sort order (:asc or :desc, defaults to :desc)
    * `:search` - Text search across name and slug fields
    * `:status` - Filter by active status (boolean or "all")

  ## Examples

      iex> list_organizations_with_stats_filtered(sort: :name, order: :asc, search: "acme")
      [%{id: 1, name: "Acme Corp", ...}, ...]
  """
  def list_organizations_with_stats_filtered(opts \\ []) do
    base_query =
      from(o in Organization,
        left_join: u in User,
        on: u.organization_id == o.id and u.active == true,
        group_by: o.id,
        select: %{
          id: o.id,
          name: o.name,
          slug: o.slug,
          active: o.active,
          user_count: count(u.id),
          inserted_at: o.inserted_at,
          updated_at: o.updated_at
        }
      )

    base_query
    |> apply_org_stats_filters(opts)
    |> apply_org_stats_search(opts[:search])
    |> apply_org_stats_sorting(opts[:sort], opts[:order])
    |> Repo.all()
  end

  defp apply_org_stats_filters(query, opts) do
    maybe_filter_org_stats_by_status(query, opts[:status])
  end

  defp maybe_filter_org_stats_by_status(query, nil),
    do: where(query, [o], o.active == true)

  defp maybe_filter_org_stats_by_status(query, ""),
    do: where(query, [o], o.active == true)

  defp maybe_filter_org_stats_by_status(query, "all"), do: query
  defp maybe_filter_org_stats_by_status(query, true), do: where(query, [o], o.active == true)

  defp maybe_filter_org_stats_by_status(query, "true"),
    do: where(query, [o], o.active == true)

  defp maybe_filter_org_stats_by_status(query, false), do: where(query, [o], o.active == false)

  defp maybe_filter_org_stats_by_status(query, "false"),
    do: where(query, [o], o.active == false)

  defp maybe_filter_org_stats_by_status(query, _), do: where(query, [o], o.active == true)

  defp apply_org_stats_search(query, nil), do: query
  defp apply_org_stats_search(query, ""), do: query

  defp apply_org_stats_search(query, search_term) when is_binary(search_term) do
    search_pattern = "%#{search_term}%"

    where(
      query,
      [o],
      like(o.name, ^search_pattern) or like(o.slug, ^search_pattern)
    )
  end

  defp apply_org_stats_sorting(query, nil, _), do: order_by(query, [o], desc: o.inserted_at)
  defp apply_org_stats_sorting(query, "", _), do: order_by(query, [o], desc: o.inserted_at)

  defp apply_org_stats_sorting(query, sort_field, order)
       when sort_field in [:name, :slug, :inserted_at, :updated_at] do
    order_atom = if order == :desc or order == "desc", do: :desc, else: :asc
    order_by(query, [o], ^[{order_atom, sort_field}])
  end

  defp apply_org_stats_sorting(query, _sort_field, _order),
    do: order_by(query, [o], desc: o.inserted_at)

  @doc """
  Gets system stats.
  """
  def get_system_stats do
    %{
      total_users: count_users(),
      total_organizations: count_organizations(),
      organization_count: count_organizations(),
      active_organization_count: count_organizations(),
      active_users: count_users(),
      active_organizations: count_organizations(),
      super_admin_count: count_global_admins(),
      recent_users: get_recent_users()
    }
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
  Counts organizations.
  """
  def count_organizations do
    from(o in Organization, where: o.active == true)
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Cleanup expired invitations with organization parameter.
  """
  def cleanup_expired_invitations(organization_id) do
    current_time = DateTime.utc_now()

    from(i in Invitation,
      where: i.organization_id == ^organization_id and i.expires_at < ^current_time
    )
    |> Repo.delete_all()
  end

  @doc """
  Cleanup inactive organizations.
  """
  def cleanup_inactive_organizations(cutoff_date) do
    from(o in Organization,
      where: o.active == false and o.updated_at < ^cutoff_date
    )
    |> Repo.delete_all()
    |> elem(0)
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
  Counts inactive organizations since a given date.
  """
  def count_inactive_organizations_since(cutoff_date) do
    from(o in Organization,
      where: o.active == false and o.updated_at < ^cutoff_date
    )
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Gets recent users (compatibility function).
  """
  def get_recent_users(limit \\ 5) do
    from(u in User,
      where: u.active == true,
      order_by: [desc: u.inserted_at],
      limit: ^limit,
      preload: [:organization]
    )
    |> Repo.all()
  end

  @doc """
  Counts active organizations (compatibility function).
  """
  def count_active_organizations do
    count_organizations()
  end

  @doc """
  Counts global admins.
  """
  def count_global_admins do
    global_org = get_global_organization()

    if global_org do
      count_users(global_org.id)
    else
      0
    end
  end

  @doc """
  Counts users created since a given date.
  """
  def count_users_since(date) do
    from(u in User,
      where: u.active == true and u.inserted_at >= ^date
    )
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Counts users by role in a specific organization.
  """
  def count_users_by_role(organization_id, role) do
    from(u in User,
      where: u.organization_id == ^organization_id and u.role == ^role and u.active == true
    )
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Counts users by role globally.
  """
  def count_users_by_role(role) do
    from(u in User,
      where: u.role == ^role and u.active == true
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
  Counts organizations created since a given date.
  """
  def count_organizations_since(date) do
    from(o in Organization,
      where: o.active == true and o.inserted_at >= ^date
    )
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Counts users by role globally.
  """
  def count_users_by_role_globally(role) do
    count_users_by_role(role)
  end

  @doc """
  Counts active users.
  """
  def count_active_users do
    count_users()
  end

  @doc """
  Counts inactive users.
  """
  def count_inactive_users do
    from(u in User, where: u.active == false)
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
  Counts organizations created before a given date.
  """
  def count_organizations_created_before(date) do
    from(o in Organization,
      where: o.active == true and o.inserted_at < ^date
    )
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Counts users created before a given date.
  """
  def count_users_created_before(date) do
    from(u in User,
      where: u.active == true and u.inserted_at < ^date
    )
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

  @doc """
  Adds an application to a group.
  """
  def add_application_to_group(%Group{} = group, application_id, application_type)
      when application_type in ["oauth2", "saml"] do
    # Handle both string and integer application IDs
    app_id =
      if is_binary(application_id), do: String.to_integer(application_id), else: application_id

    %GroupApplication{}
    |> GroupApplication.changeset(%{
      group_id: group.id,
      application_id: app_id,
      application_type: application_type
    })
    |> Repo.insert()
  end

  # Private helper functions for certificate management

  defp deactivate_existing_active_certificates(organization_id, usage, exclude_id \\ nil) do
    query =
      from(c in Certificate,
        where: c.organization_id == ^organization_id and c.usage == ^usage and c.is_active == true
      )

    query =
      if exclude_id do
        from(c in query, where: c.id != ^exclude_id)
      else
        query
      end

    query
    |> Repo.update_all(set: [is_active: false])
  end

  ## Groups

  @doc """
  Returns the list of groups for an organization.
  """
  def list_groups(%Organization{id: org_id}) do
    Group
    |> where([g], g.organization_id == ^org_id)
    |> order_by([g], asc: g.name)
    |> Repo.all()
  end

  @doc """
  Returns a filtered and sorted list of groups for an organization.

  ## Options
    * `:sort` - Field to sort by (atom, e.g., :name, :inserted_at)
    * `:order` - Sort order (:asc or :desc, defaults to :asc)
    * `:search` - Text search across name and description fields
    * `:status` - Filter by is_active status (boolean or "all")

  ## Examples

      iex> list_groups_filtered(org, sort: :name, order: :desc, search: "admin")
      [%Group{}, ...]
  """
  def list_groups_filtered(%Organization{id: org_id}, opts \\ []) do
    query =
      from(g in Group,
        where: g.organization_id == ^org_id
      )

    query
    |> apply_group_filters(opts)
    |> apply_group_search(opts[:search])
    |> apply_group_sorting(opts[:sort], opts[:order])
    |> Repo.all()
  end

  defp apply_group_filters(query, opts) do
    maybe_filter_group_by_status(query, opts[:status])
  end

  defp maybe_filter_group_by_status(query, nil),
    do: query

  defp maybe_filter_group_by_status(query, ""),
    do: query

  defp maybe_filter_group_by_status(query, "all"), do: query

  defp maybe_filter_group_by_status(query, true),
    do: where(query, [g], g.is_active == true)

  defp maybe_filter_group_by_status(query, "true"),
    do: where(query, [g], g.is_active == true)

  defp maybe_filter_group_by_status(query, false),
    do: where(query, [g], g.is_active == false)

  defp maybe_filter_group_by_status(query, "false"),
    do: where(query, [g], g.is_active == false)

  defp maybe_filter_group_by_status(query, _),
    do: query

  defp apply_group_search(query, nil), do: query
  defp apply_group_search(query, ""), do: query

  defp apply_group_search(query, search_term) when is_binary(search_term) do
    search_pattern = "%#{search_term}%"

    where(
      query,
      [g],
      like(g.name, ^search_pattern) or like(g.description, ^search_pattern)
    )
  end

  defp apply_group_sorting(query, nil, _),
    do: order_by(query, [g], asc: g.name)

  defp apply_group_sorting(query, "", _), do: order_by(query, [g], asc: g.name)

  defp apply_group_sorting(query, sort_field, order)
       when sort_field in [:name, :description, :is_active, :inserted_at, :updated_at] do
    order_atom = if order == :asc or order == "asc", do: :asc, else: :desc
    order_by(query, [g], ^[{order_atom, sort_field}])
  end

  defp apply_group_sorting(query, _sort_field, _order),
    do: order_by(query, [g], asc: g.name)

  @doc """
  Gets a single group by ID within an organization.
  """
  def get_group!(id, %Organization{id: org_id}) do
    Group
    |> where([g], g.id == ^id and g.organization_id == ^org_id)
    |> Repo.one!()
  end

  @doc """
  Creates a group.
  """
  def create_group(attrs \\ %{}) do
    %Group{}
    |> Group.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a group.
  """
  def update_group(%Group{} = group, attrs) do
    group
    |> Group.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a group.
  """
  def delete_group(%Group{} = group) do
    Repo.delete(group)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking group changes.
  """
  def change_group(%Group{} = group, attrs \\ %{}) do
    Group.changeset(group, attrs)
  end

  @doc """
  Adds a user to a group.
  """
  def add_user_to_group(%User{} = user, %Group{} = group) do
    %GroupMembership{}
    |> GroupMembership.changeset(%{user_id: user.id, group_id: group.id})
    |> Repo.insert()
  end

  @doc """
  Removes a user from a group.
  """
  def remove_user_from_group(%User{id: user_id}, %Group{id: group_id}) do
    from(gm in GroupMembership,
      where: gm.user_id == ^user_id and gm.group_id == ^group_id
    )
    |> Repo.delete_all()
  end

  @doc """
  Lists all users in a group.
  """
  def list_group_members(%Group{} = group) do
    group
    |> Repo.preload(:users)
    |> Map.get(:users)
  end

  @doc """
  Lists all groups for a user.
  """
  def list_user_groups(%User{} = user) do
    user
    |> Repo.preload(:groups)
    |> Map.get(:groups)
  end

  @doc """
  Removes an application from a group by member ID.
  """
  def remove_application_from_group(%Group{id: group_id}, member_id) do
    from(ga in GroupApplication,
      where: ga.id == ^member_id and ga.group_id == ^group_id
    )
    |> Repo.delete_all()
  end

  ## SCIM Provisioning Functions

  @doc """
  Gets a user by external_id within an organization.

  Returns nil if user not found or external_id doesn't match organization.
  """
  def get_user_by_external_id(external_id, organization_id)
      when is_binary(external_id) and is_integer(organization_id) do
    Repo.get_by(User, external_id: external_id, organization_id: organization_id)
    |> Repo.preload(:organization)
  end

  def get_user_by_external_id(_external_id, _organization_id), do: nil

  @doc """
  Gets a group by external_id within an organization.

  Returns nil if group not found or external_id doesn't match organization.
  """
  def get_group_by_external_id(external_id, organization_id)
      when is_binary(external_id) and is_integer(organization_id) do
    Repo.get_by(Group, external_id: external_id, organization_id: organization_id)
  end

  def get_group_by_external_id(_external_id, _organization_id), do: nil

  @doc """
  Lists users for SCIM with optional filter and pagination.

  ## Options
    * `:page` - Page number (default: 1)
    * `:per_page` - Results per page (default: 25, max: 100)
    * `:filter` - SCIM filter query (not implemented yet, reserved for Phase 2)

  Note: Full SCIM filter support will be added in Phase 2 (FilterParser).
  This function currently returns all users with pagination.
  """
  def list_users_scim(organization_id, opts \\ []) do
    page = Keyword.get(opts, :page, 1)
    per_page = min(Keyword.get(opts, :per_page, 25), 100)
    offset = (page - 1) * per_page

    # Base query - returns all users (active and inactive for SCIM)
    query =
      from(u in User,
        where: u.organization_id == ^organization_id,
        preload: [:organization, :groups],
        order_by: [asc: u.id]
      )

    # NOTE: SCIM filter support will be added in Phase 2 (FilterParser implementation)
    # query = apply_scim_filter(query, opts[:filter])

    query
    |> limit(^per_page)
    |> offset(^offset)
    |> Repo.all()
  end

  @doc """
  Lists groups for SCIM with optional filter and pagination.

  ## Options
    * `:page` - Page number (default: 1)
    * `:per_page` - Results per page (default: 25, max: 100)
    * `:filter` - SCIM filter query (not implemented yet, reserved for Phase 2)

  Note: Full SCIM filter support will be added in Phase 2 (FilterParser).
  """
  def list_groups_scim(organization_id, opts \\ []) do
    page = Keyword.get(opts, :page, 1)
    per_page = min(Keyword.get(opts, :per_page, 25), 100)
    offset = (page - 1) * per_page

    query =
      from(g in Group,
        where: g.organization_id == ^organization_id,
        preload: [:users],
        order_by: [asc: g.id]
      )

    # NOTE: SCIM filter support will be added in Phase 2 (FilterParser implementation)

    query
    |> limit(^per_page)
    |> offset(^offset)
    |> Repo.all()
  end

  @doc """
  Counts users for SCIM pagination (includes inactive users).

  ## Options
    * `:filter` - SCIM filter query (reserved for Phase 2)
  """
  def count_users_scim(organization_id, _opts \\ []) do
    # NOTE: Filter support will be added in Phase 2 (FilterParser implementation)
    from(u in User,
      where: u.organization_id == ^organization_id
    )
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Counts groups for SCIM pagination.

  ## Options
    * `:filter` - SCIM filter query (reserved for Phase 2)
  """
  def count_groups_scim(organization_id, _opts \\ []) do
    # NOTE: Filter support will be added in Phase 2 (FilterParser implementation)
    from(g in Group,
      where: g.organization_id == ^organization_id
    )
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Creates a user via SCIM provisioning.

  Sets scim_created_at and scim_updated_at timestamps.
  Generates a random password if not provided.
  """
  def create_user_scim(attrs, organization_id) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    # Generate secure random password if not provided
    attrs =
      if Map.get(attrs, "password") || Map.get(attrs, :password) do
        attrs
      else
        password = generate_random_password()
        Map.merge(attrs, %{password: password, password_confirmation: password})
      end

    attrs =
      attrs
      |> Map.put(:organization_id, organization_id)
      |> Map.put(:scim_created_at, now)
      |> Map.put(:scim_updated_at, now)

    %User{}
    |> User.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a user via SCIM provisioning.

  Updates scim_updated_at timestamp.
  """
  def update_user_scim(%User{} = user, attrs) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    attrs = Map.put(attrs, :scim_updated_at, now)

    user
    |> User.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Applies SCIM PATCH operations to a user.

  This is a placeholder for Phase 5 implementation.
  SCIM PATCH operations (add, remove, replace) will be implemented
  when the SCIM Users controller is built.

  ## Parameters
    * `user` - The user to patch
    * `patch_ops` - List of SCIM patch operations

  ## Example patch_ops structure:
      [
        %{"op" => "replace", "path" => "active", "value" => false},
        %{"op" => "add", "path" => "emails", "value" => [%{"value" => "new@example.com"}]}
      ]
  """
  def patch_user_scim(%User{} = _user, _patch_ops) do
    {:error, :not_implemented}
  end

  @doc """
  Creates a group via SCIM provisioning.

  Sets scim_created_at and scim_updated_at timestamps.
  """
  def create_group_scim(attrs, organization_id) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    attrs =
      attrs
      |> Map.put(:organization_id, organization_id)
      |> Map.put(:scim_created_at, now)
      |> Map.put(:scim_updated_at, now)

    %Group{}
    |> Group.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a group via SCIM provisioning.

  Updates scim_updated_at timestamp.
  """
  def update_group_scim(%Group{} = group, attrs) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    attrs = Map.put(attrs, :scim_updated_at, now)

    group
    |> Group.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Applies SCIM PATCH operations to a group.

  This is a placeholder for Phase 6 implementation.
  SCIM PATCH operations for groups (especially members array management)
  will be implemented when the SCIM Groups controller is built.

  ## Parameters
    * `group` - The group to patch
    * `patch_ops` - List of SCIM patch operations
  """
  def patch_group_scim(%Group{} = _group, _patch_ops) do
    {:error, :not_implemented}
  end

  # Private helper function to generate secure random password
  defp generate_random_password do
    # Generate a 24-character random password that meets complexity requirements
    # Includes uppercase, lowercase, digits, and special characters
    upper = Enum.take_random(?A..?Z, 6) |> List.to_string()
    lower = Enum.take_random(?a..?z, 6) |> List.to_string()
    digits = Enum.take_random(?0..?9, 6) |> List.to_string()
    special = Enum.take_random(~c"!@#$%^&*", 6) |> List.to_string()

    (upper <> lower <> digits <> special)
    |> String.graphemes()
    |> Enum.shuffle()
    |> Enum.join()
  end
end
