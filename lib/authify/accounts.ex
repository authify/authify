defmodule Authify.Accounts do
  @moduledoc """
  Simplified Accounts context for single organization model.
  """

  import Ecto.Query, warn: false

  alias Authify.Accounts.{
    Invitation,
    Organization,
    User,
    UserEmail
  }

  alias Authify.FilterSort
  alias Authify.Repo

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

  defp maybe_filter_organization_by_status(query, status),
    do: FilterSort.apply_status_filter(query, :active, status)

  defp apply_organization_search(query, search),
    do: FilterSort.apply_multi_text_filter(query, [:name, :slug], search)

  @organization_sort_fields [:name, :slug, :inserted_at, :updated_at]

  defp apply_organization_sorting(query, sort, order),
    do:
      FilterSort.apply_sort(query, sort, order, @organization_sort_fields, default: [asc: :name])

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

  defp maybe_filter_by_status(query, status),
    do: FilterSort.apply_status_filter(query, :active, status)

  defp apply_user_search(query, nil), do: query
  defp apply_user_search(query, ""), do: query

  defp apply_user_search(query, search_term) when is_binary(search_term) do
    search_pattern = "%#{search_term}%"

    # Search across user emails and names
    query
    |> join(:left, [u], ue in UserEmail, on: ue.user_id == u.id)
    |> where(
      [u, ue],
      like(ue.value, ^search_pattern) or
        like(fragment("CONCAT(?, ' ', ?)", u.first_name, u.last_name), ^search_pattern)
    )
    |> distinct([u], u.id)
  end

  defp apply_user_sorting(query, nil, _) do
    # Default sort by primary email
    query
    |> join(:left, [u], ue in UserEmail, on: ue.user_id == u.id and ue.primary == true)
    |> order_by([u, ue], asc: ue.value)
  end

  defp apply_user_sorting(query, "", _) do
    # Default sort by primary email
    query
    |> join(:left, [u], ue in UserEmail, on: ue.user_id == u.id and ue.primary == true)
    |> order_by([u, ue], asc: ue.value)
  end

  defp apply_user_sorting(query, sort_field, order)
       when sort_field in [:email, :first_name, :last_name, :role, :inserted_at] do
    order_atom = if order == :desc or order == "desc", do: :desc, else: :asc

    case sort_field do
      :email ->
        # Sort by primary email value
        query
        |> join(:left, [u], ue in UserEmail, on: ue.user_id == u.id and ue.primary == true)
        |> order_by([u, ue], [{^order_atom, ue.value}])

      _ ->
        # Sort by user field
        order_by(query, [u], ^[{order_atom, sort_field}])
    end
  end

  defp apply_user_sorting(query, _sort_field, _order) do
    # Default sort by primary email
    query
    |> join(:left, [u], ue in UserEmail, on: ue.user_id == u.id and ue.primary == true)
    |> order_by([u, ue], asc: ue.value)
  end

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
  Creates a user.
  """
  def create_user(attrs \\ %{}) do
    normalized_attrs =
      normalize_user_email_attrs(attrs, Map.get(attrs, "email"),
        default_type: "work",
        default_primary: true
      )

    %User{}
    |> User.registration_changeset(normalized_attrs)
    |> Repo.insert()
  end

  @doc """
  Creates an organization with an admin user.
  """
  def create_organization_with_admin(org_attrs, user_attrs) do
    normalized_user_attrs =
      normalize_user_email_attrs(user_attrs, Map.get(user_attrs, "email"),
        default_type: "work",
        default_primary: true
      )

    Repo.transaction(fn ->
      with {:ok, organization} <- create_organization(org_attrs),
           {:ok, {organization, user}} <-
             create_admin_user_for_organization(organization, normalized_user_attrs) do
        {organization, user}
      else
        {:error, changeset} -> Repo.rollback(changeset)
      end
    end)
  end

  defp create_admin_user_for_organization(organization, user_attrs) do
    # Generate unique username based on preferred username
    preferred_username = Map.get(user_attrs, "username", "admin")
    unique_username = User.generate_unique_username(preferred_username, organization.id, Repo)

    normalized_user_attrs =
      normalize_user_email_attrs(user_attrs, Map.get(user_attrs, "email"),
        default_type: "work",
        default_primary: true
      )

    user_attrs_with_org =
      normalized_user_attrs
      |> Map.put("organization_id", organization.id)
      |> Map.put("role", "admin")
      |> Map.put("username", unique_username)

    case create_user(user_attrs_with_org) do
      {:ok, user} -> {:ok, {organization, user}}
      {:error, changeset} -> {:error, changeset}
    end
  end

  @doc """
  Updates a user.

  Note: Email management is now done through the user_emails association.
  Use add_email_to_user/2, set_primary_email/2, or verify_email/1 for email operations.
  """
  def update_user(%User{} = user, attrs) do
    normalized_attrs =
      normalize_user_email_attrs(attrs, Map.get(attrs, "email"),
        default_type: "work",
        default_primary: true
      )

    user
    |> Repo.preload(:emails, force: true)
    |> User.changeset(normalized_attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a user.
  """
  def delete_user(%User{} = user) do
    result = Repo.delete(user)

    case result do
      {:ok, deleted_user} ->
        Authify.SCIM.Provisioning.broadcast_resource_event(deleted_user, :deleted, :user)
        {:ok, deleted_user}

      error ->
        error
    end
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

  Note: Email management is now done through the user_emails association.
  """
  def change_user_form(%User{} = user, attrs \\ %{}) do
    user
    |> Ecto.Changeset.cast(attrs, [
      :first_name,
      :last_name,
      :username,
      :password,
      :password_confirmation
    ])
  end

  @doc """
  Updates a user's profile information (name, username).

  Note: Email management is now done through the user_emails association.
  Use add_email_to_user/2, set_primary_email/2, or verify_email/1 for email operations.
  """
  def update_user_profile(%User{} = user, attrs) do
    normalized_attrs =
      normalize_user_email_attrs(attrs, Map.get(attrs, "email"),
        default_type: "work",
        default_primary: true
      )

    user_editable = ~w(first_name last_name username theme_preference
                       avatar_url locale zoneinfo phone_number website)
    filtered_attrs = Map.take(normalized_attrs, user_editable)

    user
    |> Repo.preload(:emails)
    |> User.changeset(filtered_attrs)
    |> Repo.update()
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

    user_attrs_with_emails =
      normalize_user_email_attrs(user_attrs_with_org, Map.get(user_attrs, "email"),
        default_type: "work",
        default_primary: true
      )

    case create_user(user_attrs_with_emails) do
      {:ok, user} -> {:ok, Repo.preload(user, :emails)}
      {:error, changeset} -> {:error, changeset}
    end
  end

  @doc """
  Creates a user with default role in an organization.
  """
  def create_user_with_role(user_attrs, organization_id) do
    create_user_with_role(user_attrs, organization_id, "user")
  end

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

  @doc """
  Creates a user and emits event to trigger email verification workflow.

  This should be used when creating users directly (not through invitation).
  Users created through invitations have already verified their email.
  """
  def create_user_and_send_verification(user_attrs, organization_id, role \\ "user") do
    case create_user_with_role(user_attrs, organization_id, role) do
      {:ok, user} ->
        user = Repo.preload(user, [:organization, :emails])

        # Emit event to trigger email verification workflow (token generation + email)
        case Authify.Tasks.EventHandler.handle_event(:email_verification_needed, %{
               user_id: user.id,
               organization_id: organization_id
             }) do
          {:ok, _task} ->
            require Logger
            Logger.info("Email verification workflow triggered for user #{user.id}")

          {:error, reason} ->
            require Logger
            Logger.error("Failed to trigger email verification workflow: #{inspect(reason)}")
        end

        {:ok, user}

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

  ## User Email Management

  @doc """
  Gets a user by email address (searches across all user emails).
  Returns the first user found with this email, preloaded with organization.
  """
  def get_user_by_email(email) when is_binary(email) do
    from(ue in UserEmail,
      where: ue.value == ^email,
      join: u in User,
      on: ue.user_id == u.id,
      where: u.active == true,
      preload: [user: :organization],
      limit: 1
    )
    |> Repo.one()
    |> case do
      nil -> nil
      user_email -> user_email.user
    end
  end

  def get_user_by_email(_), do: nil

  @doc """
  Gets a user by primary email address.
  This is the main function used for login authentication.
  """
  def get_user_by_primary_email(email) when is_binary(email) do
    from(ue in UserEmail,
      where: ue.value == ^email and ue.primary == true,
      join: u in User,
      on: ue.user_id == u.id,
      where: u.active == true,
      preload: [user: :organization],
      limit: 1
    )
    |> Repo.one()
    |> case do
      nil -> nil
      user_email -> user_email.user
    end
  end

  def get_user_by_primary_email(_), do: nil

  @doc """
  Gets a user by email and organization.
  Searches across all user emails within the specified organization.
  """
  def get_user_by_email_and_organization(email, organization_id)
      when is_binary(email) and is_integer(organization_id) do
    from(ue in UserEmail,
      where: ue.value == ^email,
      join: u in User,
      on: ue.user_id == u.id,
      where: u.organization_id == ^organization_id and u.active == true,
      preload: [user: :organization],
      limit: 1
    )
    |> Repo.one()
    |> case do
      nil -> nil
      user_email -> user_email.user
    end
  end

  def get_user_by_email_and_organization(_, _), do: nil

  @doc """
  Adds an additional email address to a user.

  ## Parameters
    * `user` - User struct
    * `email_attrs` - Map with :value, :type (optional), :primary (optional), :display (optional)

  ## Examples
      iex> add_email_to_user(user, %{value: "new@example.com", type: "work"})
      {:ok, %UserEmail{}}

      iex> add_email_to_user(user, %{value: "duplicate@example.com"})
      {:error, %Ecto.Changeset{}}
  """
  def add_email_to_user(%User{} = user, email_attrs) when is_map(email_attrs) do
    # Normalize to string keys for consistency with changeset
    attrs =
      email_attrs
      |> Enum.map(fn {k, v} -> {to_string(k), v} end)
      |> Map.new()
      |> Map.put("user_id", user.id)
      |> Map.put_new("type", "work")
      |> Map.put_new("primary", false)

    %UserEmail{}
    |> UserEmail.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Sets a specific email as the primary email for a user.
  Automatically demotes the current primary email.

  ## Parameters
    * `user` - User struct
    * `email_id` - ID of the email to set as primary

  ## Returns
    * `{:ok, user_email}` - Successfully updated
    * `{:error, :email_not_found}` - Email doesn't exist or doesn't belong to user
    * `{:error, changeset}` - Validation failed
  """
  def set_primary_email(%User{} = user, email_id) when is_integer(email_id) do
    Repo.transaction(fn ->
      # Get the email to promote
      email_to_promote = Repo.get_by(UserEmail, id: email_id, user_id: user.id)

      unless email_to_promote do
        Repo.rollback(:email_not_found)
      end

      # Demote current primary email
      from(ue in UserEmail,
        where: ue.user_id == ^user.id and ue.primary == true
      )
      |> Repo.update_all(set: [primary: false])

      # Promote new primary email
      email_to_promote
      |> Ecto.Changeset.change(%{primary: true})
      |> Repo.update!()
    end)
  end

  @doc """
  Deletes an email address from a user's account.

  Cannot delete the primary email address - user must first set another email as primary.

  ## Parameters
    * `user` - User struct
    * `email_id` - ID of the email to delete

  ## Returns
    * `{:ok, user_email}` - Successfully deleted
    * `{:error, :email_not_found}` - Email doesn't exist or doesn't belong to user
    * `{:error, :cannot_delete_primary}` - Cannot delete primary email
  """
  def delete_email(%User{} = user, email_id) when is_integer(email_id) do
    case Repo.get_by(UserEmail, id: email_id, user_id: user.id) do
      nil ->
        {:error, :email_not_found}

      %UserEmail{primary: true} ->
        {:error, :cannot_delete_primary}

      email ->
        Repo.delete(email)
    end
  end

  @doc """
  Marks an email as verified.

  ## Parameters
    * `email_id` - ID of the email to verify

  ## Returns
    * `{:ok, user_email}` - Successfully verified
    * `{:error, :email_not_found}` - Email doesn't exist
    * `{:error, changeset}` - Verification failed
  """
  def verify_email(email_id) when is_integer(email_id) do
    case Repo.get(UserEmail, email_id) do
      nil ->
        {:error, :email_not_found}

      email ->
        email
        |> UserEmail.verify_changeset()
        |> Repo.update()
    end
  end

  @doc """
  Emits event to trigger email verification workflow.

  ## Parameters
    * `user` - User struct (must have organization preloaded)
    * `email` - UserEmail struct to verify

  ## Returns
    * `{:ok, user_email}` - Event triggered successfully
    * `{:error, reason}` - Event trigger failed
  """
  def send_email_verification(%User{} = user, %UserEmail{} = _email) do
    # Emit event to trigger email verification workflow (token generation + email)
    case Authify.Tasks.EventHandler.handle_event(:email_verification_needed, %{
           user_id: user.id,
           organization_id: user.organization_id
         }) do
      {:ok, _task} ->
        require Logger
        Logger.info("Email verification workflow triggered for user #{user.id}")
        {:ok, user}

      {:error, reason} ->
        require Logger
        Logger.error("Failed to trigger email verification workflow: #{inspect(reason)}")
        {:error, reason}
    end
  end

  ## Authentication

  @doc """
  Authenticates a user with email and password within an organization.
  Uses primary email for authentication.
  """
  def authenticate_user(email, password, organization_id) do
    # Query using the optimized covering index on user_emails
    user =
      from(u in User,
        join: ue in UserEmail,
        on: ue.user_id == u.id,
        where:
          ue.value == ^email and ue.primary == true and
            u.organization_id == ^organization_id and u.active == true,
        preload: [:organization, :emails],
        limit: 1
      )
      |> Repo.one()

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
  Builds the full URL for resetting a password.

  The user must have the organization association preloaded.
  """
  def build_password_reset_url(organization, token) do
    # Get the effective email link domain for this organization
    # (uses configured email_link_domain or falls back to default domain)
    domain = Authify.Organizations.get_email_link_domain(organization)

    # Build the reset URL with proper protocol/port for environment
    "#{build_base_url(domain)}/password_reset/#{token}/edit"
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

  ## Overloads

  ### With UserEmail
  Generates token for a specific email address.

  Parameters:
    * `email` - UserEmail struct to generate verification token for

  Returns:
    * `{:ok, user_email, plaintext_token}` - Token generated successfully
    * `{:error, changeset}` - Token generation failed

  ### With User
  Generates token for user's primary email (convenience function).

  Parameters:
    * `user` - User struct (will be preloaded with emails if needed)

  Returns:
    * `{:ok, user_email, plaintext_token}` - Token generated successfully
    * `{:error, changeset}` - Token generation failed
  """
  def generate_email_verification_token(arg)

  def generate_email_verification_token(%UserEmail{} = email) do
    # Generate random token
    token = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

    # Update email with verification token
    changeset = UserEmail.verification_token_changeset(email, token)

    case Repo.update(changeset) do
      {:ok, updated_email} ->
        {:ok, updated_email, token}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  def generate_email_verification_token(user) when is_struct(user, User) do
    # Preload emails if not already loaded
    user = Repo.preload(user, :emails)

    # Get primary email
    primary_email = User.get_primary_email(user)

    # Call the UserEmail version
    generate_email_verification_token(primary_email)
  end

  @doc """
  Gets user by email verification token.
  Hashes the provided token and looks up in user_emails table.
  """
  def get_user_by_email_verification_token(nil), do: nil

  def get_user_by_email_verification_token(token) do
    # Hash the token for lookup
    token_hash = :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)

    from(ue in UserEmail,
      where:
        ue.verification_token == ^token_hash and
          ue.verification_expires_at > ^DateTime.utc_now(),
      join: u in User,
      on: ue.user_id == u.id,
      preload: [user: :organization],
      limit: 1
    )
    |> Repo.one()
    |> case do
      nil -> nil
      user_email -> user_email.user
    end
  end

  @doc """
  Verifies email with token.
  Hashes the provided token and looks up in user_emails table.
  Marks the email as verified and returns the user.
  """
  def verify_email_with_token(token) do
    # Hash the incoming token to look up in database
    token_hash = :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)

    # First check if email exists with this token (regardless of expiration)
    email_with_token =
      from(ue in UserEmail,
        where: ue.verification_token == ^token_hash,
        preload: [:user]
      )
      |> Repo.one()

    case email_with_token do
      nil ->
        {:error, :token_not_found}

      email ->
        # Check if token is expired
        if email.verification_expires_at &&
             DateTime.compare(email.verification_expires_at, DateTime.utc_now()) == :lt do
          {:error, :token_expired}
        else
          changeset = UserEmail.verify_changeset(email)

          case Repo.update(changeset) do
            {:ok, updated_email} ->
              # Return the user with updated email preloaded
              user = Repo.preload(updated_email.user, [:organization, :emails], force: true)
              {:ok, user}

            {:error, changeset} ->
              {:error, changeset}
          end
        end
    end
  end

  @doc """
  Cleanup expired email verification tokens.
  """
  def cleanup_expired_email_verification_tokens do
    from(ue in UserEmail,
      where:
        not is_nil(ue.verification_token) and
          ue.verification_expires_at < ^DateTime.utc_now()
    )
    |> Repo.update_all(set: [verification_token: nil, verification_expires_at: nil])
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
  Cleanup inactive organizations.
  """
  def cleanup_inactive_organizations(cutoff_date) do
    from(o in Organization,
      where: o.active == false and o.updated_at < ^cutoff_date
    )
    |> Repo.delete_all()
    |> elem(0)
  end
end
