defmodule Authify.Accounts.User do
  @moduledoc """
  User schema with single organization relationship.
  Each user belongs to exactly one organization with a specific role.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias Authify.Accounts.{
    Group,
    GroupMembership,
    Organization,
    UserEmail
  }

  @derive {Jason.Encoder,
           except: [
             :organization,
             :group_memberships,
             :groups,
             :emails,
             :hashed_password,
             :password_reset_token,
             :password_reset_expires_at,
             :password,
             :password_confirmation,
             :totp_secret,
             :totp_backup_codes,
             :scim_created_at,
             :scim_updated_at,
             :__meta__
           ]}

  @type t :: %__MODULE__{
          id: integer(),
          hashed_password: String.t(),
          first_name: String.t() | nil,
          last_name: String.t() | nil,
          username: String.t() | nil,
          organization_id: integer() | nil,
          role: String.t(),
          active: boolean(),
          organization: Organization.t(),
          emails: [UserEmail.t()],
          inserted_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  schema "users" do
    field :hashed_password, :string
    field :first_name, :string
    field :last_name, :string
    field :username, :string
    field :role, :string, default: "user"
    field :active, :boolean, default: true
    field :password_reset_token, :string
    field :plaintext_reset_token, :string, virtual: true
    field :password_reset_expires_at, :utc_datetime
    field :theme_preference, :string, default: "auto"
    field :password, :string, virtual: true
    field :password_confirmation, :string, virtual: true

    # TOTP MFA fields
    field :totp_secret, :string
    field :totp_enabled_at, :utc_datetime
    field :totp_backup_codes, :string
    field :totp_backup_codes_generated_at, :utc_datetime

    # SCIM provisioning fields
    field :external_id, :string
    field :scim_created_at, :utc_datetime
    field :scim_updated_at, :utc_datetime

    belongs_to :organization, Organization

    has_many :emails, UserEmail, on_delete: :delete_all
    has_many :group_memberships, GroupMembership, on_delete: :delete_all
    many_to_many :groups, Group, join_through: GroupMembership

    timestamps(type: :utc_datetime)
  end

  @optional_fields [
    :first_name,
    :last_name,
    :username,
    :organization_id,
    :role,
    :active,
    :theme_preference,
    :external_id
  ]
  @password_fields [:password, :password_confirmation]

  @doc false
  def changeset(user, attrs) do
    user
    |> cast(attrs, @optional_fields ++ @password_fields)
    |> validate_username()
    |> validate_role()
    |> validate_password()
    |> validate_theme_preference()
    |> validate_external_id()
    |> foreign_key_constraint(:organization_id, name: "users_organization_id_fkey")
  end

  @doc """
  Changeset for user registration with email.

  Requires at least one email address with primary=true.
  """
  def registration_changeset(user, attrs) do
    user
    |> changeset(attrs)
    |> cast_assoc(:emails, required: true, with: &UserEmail.nested_changeset/2)
    |> validate_has_primary_email()
    |> validate_required([:password])
    |> put_password_hash()
  end

  @doc """
  Changeset for updating user emails.

  Ensures user always has exactly one primary email.
  """
  def email_changeset(user, attrs) do
    user
    |> cast(attrs, [])
    |> cast_assoc(:emails, with: &UserEmail.nested_changeset/2)
    |> validate_has_primary_email()
    |> validate_has_at_least_one_email()
  end

  @doc false
  def password_changeset(user, attrs) do
    user
    |> cast(attrs, @password_fields)
    |> validate_password()
    |> put_password_hash()
  end

  @doc """
  Returns the primary email for a user.

  Raises if user has no primary email (should never happen with proper validation).
  Automatically preloads emails if not already loaded.
  """
  def get_primary_email(%__MODULE__{emails: emails}) when is_list(emails) do
    case Enum.find(emails, & &1.primary) do
      nil -> raise "User has no primary email"
      email -> email
    end
  end

  def get_primary_email(%__MODULE__{} = user) do
    # Emails not loaded, we need to query directly
    import Ecto.Query

    case Authify.Repo.one(
           from e in UserEmail,
             where: e.user_id == ^user.id and e.primary == true
         ) do
      nil -> raise "User has no primary email"
      email -> email
    end
  end

  @doc """
  Returns the primary email value (string) for a user.
  """
  def get_primary_email_value(user) do
    get_primary_email(user).value
  end

  @doc """
  Checks if a user's primary email is verified.
  """
  def primary_email_verified?(%__MODULE__{} = user) do
    primary = get_primary_email(user)
    not is_nil(primary.verified_at)
  end

  # Validates that user has at least one email marked as primary
  defp validate_has_primary_email(changeset) do
    case get_change(changeset, :emails) do
      nil ->
        # No changes to emails, check existing
        case changeset.data do
          %{emails: %Ecto.Association.NotLoaded{}} ->
            # Emails not loaded, can't validate
            changeset

          %{emails: emails} when is_list(emails) ->
            if Enum.any?(emails, & &1.primary) do
              changeset
            else
              add_error(changeset, :emails, "must have exactly one primary email")
            end

          _ ->
            changeset
        end

      emails ->
        # Changes to emails, validate changesets
        primary_count =
          Enum.count(emails, fn email_changeset ->
            case email_changeset do
              %Ecto.Changeset{} -> get_field(email_changeset, :primary) == true
              %UserEmail{} -> email_changeset.primary == true
              _ -> false
            end
          end)

        cond do
          primary_count == 0 ->
            add_error(changeset, :emails, "must have exactly one primary email")

          primary_count > 1 ->
            add_error(changeset, :emails, "can only have one primary email")

          true ->
            changeset
        end
    end
  end

  # Validates that user has at least one email
  defp validate_has_at_least_one_email(changeset) do
    case get_change(changeset, :emails) do
      nil ->
        changeset

      emails ->
        # Filter out emails marked for deletion
        active_emails =
          Enum.reject(emails, fn email_changeset ->
            case email_changeset do
              %Ecto.Changeset{} -> get_change(email_changeset, :action) == :delete
              _ -> false
            end
          end)

        if Enum.empty?(active_emails) do
          add_error(changeset, :emails, "must have at least one email address")
        else
          changeset
        end
    end
  end

  defp validate_username(changeset) do
    changeset
    |> validate_length(:username, min: 3, max: 50)
    |> validate_format(:username, ~r/^[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]$/,
      message:
        "must start and end with alphanumeric characters and can contain letters, numbers, dots, hyphens, and underscores"
    )
    |> unique_constraint([:username, :organization_id],
      message: "username already exists in this organization"
    )
  end

  defp validate_role(changeset) do
    validate_inclusion(changeset, :role, ["admin", "user"])
  end

  defp validate_theme_preference(changeset) do
    validate_inclusion(changeset, :theme_preference, ["auto", "light", "dark"])
  end

  defp validate_external_id(changeset) do
    changeset
    |> validate_length(:external_id, max: 255)
    |> validate_format(:external_id, ~r/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/,
      message:
        "must start with alphanumeric character and can contain letters, numbers, dots, hyphens, and underscores"
    )
    |> validate_external_id_immutability()
    |> unique_constraint([:external_id, :organization_id],
      message: "external_id already exists in this organization"
    )
  end

  # Ensure external_id cannot be changed once set
  defp validate_external_id_immutability(changeset) do
    case {get_field(changeset, :id), get_change(changeset, :external_id)} do
      {id, new_external_id} when not is_nil(id) and not is_nil(new_external_id) ->
        # This is an update (user has an id)
        old_external_id = changeset.data.external_id

        if old_external_id && old_external_id != new_external_id do
          add_error(changeset, :external_id, "cannot be changed once set")
        else
          changeset
        end

      _ ->
        # This is a new user or external_id is not being changed
        changeset
    end
  end

  defp validate_password(%Ecto.Changeset{valid?: false} = changeset), do: changeset

  defp validate_password(changeset) do
    changeset
    |> validate_length(:password,
      min: 8,
      max: 100,
      message: "must be between 8 and 100 characters"
    )
    |> validate_confirmation(:password, message: "does not match password")
    |> validate_password_complexity()
  end

  defp validate_password_complexity(changeset) do
    case get_change(changeset, :password) do
      nil ->
        changeset

      password when is_binary(password) ->
        changeset
        |> validate_password_has_uppercase(password)
        |> validate_password_has_lowercase(password)
        |> validate_password_has_digit(password)
        |> validate_password_has_special_char(password)
        |> validate_password_not_common(password)

      _ ->
        changeset
    end
  end

  defp validate_password_has_uppercase(changeset, password) do
    if Regex.match?(~r/[A-Z]/, password) do
      changeset
    else
      add_error(changeset, :password, "must contain at least one uppercase letter")
    end
  end

  defp validate_password_has_lowercase(changeset, password) do
    if Regex.match?(~r/[a-z]/, password) do
      changeset
    else
      add_error(changeset, :password, "must contain at least one lowercase letter")
    end
  end

  defp validate_password_has_digit(changeset, password) do
    if Regex.match?(~r/[0-9]/, password) do
      changeset
    else
      add_error(changeset, :password, "must contain at least one number")
    end
  end

  defp validate_password_has_special_char(changeset, password) do
    if Regex.match?(~r/[^A-Za-z0-9]/, password) do
      changeset
    else
      add_error(
        changeset,
        :password,
        "must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)"
      )
    end
  end

  defp validate_password_not_common(changeset, password) do
    # List of common passwords to reject
    common_passwords = [
      "password",
      "123456",
      "12345678",
      "qwerty",
      "abc123",
      "password123",
      "admin",
      "letmein",
      "welcome",
      "monkey",
      "1234567890",
      "password1",
      "123456789",
      "welcome123",
      "admin123",
      "root",
      "toor",
      "pass",
      "test",
      "guest",
      "user",
      "demo",
      "temp",
      "changeme",
      "default"
    ]

    if String.downcase(password) in common_passwords do
      add_error(changeset, :password, "is too common, please choose a more secure password")
    else
      changeset
    end
  end

  defp put_password_hash(
         %Ecto.Changeset{valid?: true, changes: %{password: password}} = changeset
       ) do
    put_change(changeset, :hashed_password, Bcrypt.hash_pwd_salt(password))
  end

  defp put_password_hash(changeset), do: changeset

  def apply_scim_timestamps(changeset, attrs \\ %{}) do
    changeset
    |> allow_scim_field(:scim_created_at, Map.get(attrs, :scim_created_at))
    |> allow_scim_field(:scim_updated_at, Map.get(attrs, :scim_updated_at))
  end

  defp allow_scim_field(changeset, _field, nil), do: changeset

  defp allow_scim_field(changeset, field, value) do
    Ecto.Changeset.put_change(changeset, field, value)
  end

  @doc """
  Verifies the password.
  """
  def valid_password?(%__MODULE__{hashed_password: hashed_password}, password)
      when is_binary(hashed_password) and byte_size(password) > 0 do
    Bcrypt.verify_pass(password, hashed_password)
  end

  def valid_password?(_, _) do
    Bcrypt.no_user_verify()
    false
  end

  @doc """
  Returns the user's full name.
  """
  def full_name(%__MODULE__{first_name: first_name, last_name: last_name}) do
    [first_name, last_name]
    |> Enum.filter(&(&1 && String.trim(&1) != ""))
    |> Enum.join(" ")
    |> case do
      "" -> nil
      name -> name
    end
  end

  @doc """
  Checks if user is an admin in a specific organization.
  """
  def admin?(%__MODULE__{} = user, organization_id) when is_integer(organization_id) do
    user.organization_id == organization_id and user.role == "admin" and user.active
  end

  @doc """
  Checks if user is a global admin (member of the global organization with admin role).
  """
  def global_admin?(%__MODULE__{
        organization: %{slug: "authify-global"},
        role: "admin",
        active: true
      }),
      do: true

  def global_admin?(%__MODULE__{organization: organization} = user)
      when not is_nil(organization) do
    organization.slug == "authify-global" and user.role == "admin" and user.active
  end

  def global_admin?(_), do: false

  @doc """
  Legacy function - checks if user is a super admin (global Authify admin).
  For backwards compatibility, delegates to global_admin?.
  """
  def super_admin?(%__MODULE__{} = user) do
    global_admin?(user)
  end

  def super_admin?(_), do: false

  @doc """
  Gets the user's role in a specific organization.
  """
  def role_in_organization(%__MODULE__{} = user, organization_id)
      when is_integer(organization_id) do
    if user.organization_id == organization_id and user.active do
      user.role
    else
      nil
    end
  end

  @doc """
  Checks if user is an active member of a specific organization.
  """
  def active_member_of?(%__MODULE__{} = user, organization_id) when is_integer(organization_id) do
    member_of?(user, organization_id) and user.active
  end

  @doc """
  Checks if user is an active member of a specific organization.
  """
  def member_of?(%__MODULE__{} = user, organization_id) when is_integer(organization_id) do
    user.organization_id == organization_id
  end

  @doc """
  Generates a unique username based on preferred username within an organization.
  """
  def generate_unique_username(preferred_username, organization_id, repo) do
    base_username = clean_username(preferred_username)

    if username_available?(base_username, organization_id, repo) do
      base_username
    else
      find_available_username(base_username, organization_id, repo, 1)
    end
  end

  defp clean_username(preferred_username) do
    preferred_username
    |> String.downcase()
    |> String.replace(~r/[^a-zA-Z0-9._-]/, "")
    # Limit length for suffix space
    |> String.slice(0, 30)
  end

  defp username_available?(username, organization_id, repo) do
    query =
      from(u in __MODULE__,
        where: u.username == ^username and u.organization_id == ^organization_id
      )

    repo.one(query) == nil
  end

  defp find_available_username(base_username, organization_id, repo, attempt)
       when attempt < 1000 do
    candidate = "#{base_username}#{:rand.uniform(9999)}"

    if username_available?(candidate, organization_id, repo) do
      candidate
    else
      find_available_username(base_username, organization_id, repo, attempt + 1)
    end
  end

  defp find_available_username(base_username, _organization_id, _repo, _attempt) do
    # Fallback after 1000 attempts
    "#{base_username}#{DateTime.utc_now() |> DateTime.to_unix()}"
  end

  @doc """
  Generates a secure password reset token.
  """
  def generate_password_reset_token do
    :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  end

  @doc """
  Returns a changeset for password reset token generation.
  """
  def password_reset_changeset(%__MODULE__{} = user) do
    plaintext_token = generate_password_reset_token()
    token_hash = hash_password_reset_token(plaintext_token)
    # 24 hours
    expires_at =
      DateTime.utc_now() |> DateTime.add(24 * 60 * 60, :second) |> DateTime.truncate(:second)

    user
    |> Ecto.Changeset.change(%{
      password_reset_token: token_hash,
      plaintext_reset_token: plaintext_token,
      password_reset_expires_at: expires_at
    })
  end

  @doc """
  Returns a changeset for password reset completion.
  """
  def password_reset_completion_changeset(%__MODULE__{} = user, attrs) do
    user
    |> password_changeset(attrs)
    |> Ecto.Changeset.put_change(:password_reset_token, nil)
    |> Ecto.Changeset.put_change(:password_reset_expires_at, nil)
  end

  @doc """
  Checks if a password reset token is valid and not expired.
  """
  def valid_password_reset_token?(%__MODULE__{} = user) do
    user.password_reset_token != nil and
      user.password_reset_expires_at != nil and
      DateTime.compare(DateTime.utc_now(), user.password_reset_expires_at) == :lt
  end

  def role_permits?(user, required_role, organization_id) do
    global_admin?(user) ||
      (user.active &&
         role_in_organization(user, organization_id) |> check_role_hierarchy(required_role))
  end

  defp check_role_hierarchy(user_role, required_role) do
    role_hierarchy = %{
      "user" => 1,
      "admin" => 2,
      "super_admin" => 3
    }

    user_level = Map.get(role_hierarchy, user_role, 0)
    required_level = Map.get(role_hierarchy, required_role, 999)

    user_level >= required_level
  end

  @doc """
  Hashes a password reset token for secure storage.
  Uses SHA-256 for fast hashing (tokens are already random and long).
  """
  def hash_password_reset_token(token) when is_binary(token) do
    :crypto.hash(:sha256, token)
    |> Base.encode64()
  end

  @doc """
  Verifies a plaintext reset token against a stored hash.
  Returns true if the token matches, false otherwise.
  """
  def verify_password_reset_token(plaintext_token, token_hash)
      when is_binary(plaintext_token) and is_binary(token_hash) do
    computed_hash = hash_password_reset_token(plaintext_token)
    Plug.Crypto.secure_compare(computed_hash, token_hash)
  end

  def verify_password_reset_token(_, _), do: false

  # TOTP MFA Helper Functions

  @doc """
  Checks if TOTP is enabled for the user.
  """
  def totp_enabled?(%__MODULE__{totp_enabled_at: nil}), do: false
  def totp_enabled?(%__MODULE__{}), do: true

  @doc """
  Checks if TOTP is required for the user based on organization settings.
  Returns true if the organization requires MFA but the user hasn't enabled it.
  """
  def totp_required?(%__MODULE__{} = user, organization) do
    org_requires_mfa = Authify.Configurations.get_organization_setting(organization, :require_mfa)
    org_requires_mfa && !totp_enabled?(user)
  end
end
