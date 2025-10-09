defmodule Authify.Accounts.User do
  @moduledoc """
  User schema with single organization relationship.
  Each user belongs to exactly one organization with a specific role.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias Authify.Accounts.{ApplicationGroup, Organization, UserApplicationGroup}

  @derive {Jason.Encoder,
           except: [
             :organization,
             :user_application_groups,
             :application_groups,
             :hashed_password,
             :password_reset_token,
             :password_reset_expires_at,
             :email_verification_token,
             :email_verification_expires_at,
             :password,
             :password_confirmation,
             :__meta__
           ]}

  @type t :: %__MODULE__{
          id: integer(),
          email: String.t(),
          hashed_password: String.t(),
          first_name: String.t() | nil,
          last_name: String.t() | nil,
          username: String.t() | nil,
          organization_id: integer() | nil,
          role: String.t(),
          active: boolean(),
          email_confirmed_at: DateTime.t() | nil,
          organization: Organization.t(),
          inserted_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  schema "users" do
    field :email, :string
    field :hashed_password, :string
    field :first_name, :string
    field :last_name, :string
    field :username, :string
    field :role, :string, default: "user"
    field :active, :boolean, default: true
    field :email_confirmed_at, :utc_datetime
    field :email_verification_token, :string
    field :plaintext_verification_token, :string, virtual: true
    field :email_verification_expires_at, :utc_datetime
    field :password_reset_token, :string
    field :plaintext_reset_token, :string, virtual: true
    field :password_reset_expires_at, :utc_datetime
    field :theme_preference, :string, default: "auto"
    field :password, :string, virtual: true
    field :password_confirmation, :string, virtual: true

    belongs_to :organization, Organization

    has_many :user_application_groups, UserApplicationGroup, on_delete: :delete_all
    many_to_many :application_groups, ApplicationGroup, join_through: UserApplicationGroup

    timestamps(type: :utc_datetime)
  end

  @required_fields [:email]
  @optional_fields [
    :first_name,
    :last_name,
    :username,
    :organization_id,
    :role,
    :active,
    :email_confirmed_at,
    :theme_preference
  ]
  @password_fields [:password, :password_confirmation]

  @doc false
  def changeset(user, attrs) do
    user
    |> cast(attrs, @required_fields ++ @optional_fields ++ @password_fields)
    |> validate_required(@required_fields)
    |> validate_email()
    |> validate_username()
    |> validate_role()
    |> validate_password()
    |> validate_theme_preference()
    |> foreign_key_constraint(:organization_id, name: "users_organization_id_fkey")
  end

  @doc false
  def registration_changeset(user, attrs) do
    user
    |> changeset(attrs)
    |> validate_required([:password])
    |> put_password_hash()
  end

  @doc false
  def password_changeset(user, attrs) do
    user
    |> cast(attrs, @password_fields)
    |> validate_password()
    |> put_password_hash()
  end

  defp validate_email(changeset) do
    changeset
    |> validate_format(:email, ~r/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)
    |> validate_length(:email, max: 255)
    |> unique_constraint(:email, message: "email already exists")
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
  Checks if user is a member of a specific organization.
  """
  def member_of?(%__MODULE__{} = user, organization_id) when is_integer(organization_id) do
    user.organization_id == organization_id and user.active
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

  @doc """
  Generates a secure email verification token.
  """
  def generate_email_verification_token do
    :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  end

  @doc """
  Returns a changeset for email verification token generation.
  """
  def email_verification_changeset(%__MODULE__{} = user) do
    plaintext_token = generate_email_verification_token()
    token_hash = hash_email_verification_token(plaintext_token)
    # 24 hours
    expires_at =
      DateTime.utc_now() |> DateTime.add(24 * 60 * 60, :second) |> DateTime.truncate(:second)

    user
    |> Ecto.Changeset.change(%{
      email_verification_token: token_hash,
      plaintext_verification_token: plaintext_token,
      email_verification_expires_at: expires_at
    })
  end

  @doc """
  Returns a changeset for email verification completion.
  """
  def email_verification_completion_changeset(%__MODULE__{} = user) do
    user
    |> Ecto.Changeset.change(%{
      email_verification_token: nil,
      email_verification_expires_at: nil,
      email_confirmed_at: DateTime.utc_now() |> DateTime.truncate(:second)
    })
  end

  @doc """
  Checks if an email verification token is valid and not expired.
  """
  def valid_email_verification_token?(%__MODULE__{} = user) do
    user.email_verification_token != nil and
      user.email_verification_expires_at != nil and
      DateTime.compare(DateTime.utc_now(), user.email_verification_expires_at) == :lt
  end

  @doc """
  Hashes an email verification token for secure storage.
  Uses SHA-256 for fast hashing (tokens are already random and long).
  """
  def hash_email_verification_token(token) when is_binary(token) do
    :crypto.hash(:sha256, token)
    |> Base.encode64()
  end

  @doc """
  Verifies a plaintext verification token against a stored hash.
  Returns true if the token matches, false otherwise.
  """
  def verify_email_verification_token(plaintext_token, token_hash)
      when is_binary(plaintext_token) and is_binary(token_hash) do
    computed_hash = hash_email_verification_token(plaintext_token)
    Plug.Crypto.secure_compare(computed_hash, token_hash)
  end

  def verify_email_verification_token(_, _), do: false
end
