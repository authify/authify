defmodule Authify.PasswordPolicy do
  @moduledoc """
  Resolves and applies per-organization password complexity policies.

  The effective policy for an organization is derived from its organization
  settings, falling back to a strict global default that matches Authify's
  historical hardcoded rules. This lets individual organizations relax (or
  further tighten) password requirements without affecting other tenants.
  """

  alias Authify.Configurations

  @default_policy %{
    password_min_length: 8,
    password_max_length: 100,
    password_require_uppercase: true,
    password_require_lowercase: true,
    password_require_digit: true,
    password_require_special: true,
    password_common_blocklist_enabled: true
  }

  @common_passwords [
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

  @doc """
  Returns the strict default policy, matching Authify's historical behavior.
  """
  def default_policy, do: @default_policy

  @doc """
  Resolves the effective password policy for an organization.

  Accepts an organization id, an `%Organization{}` struct, or `nil` (which
  yields the global default policy).
  """
  def resolve(nil), do: @default_policy
  def resolve(%{id: organization_id}), do: resolve(organization_id)

  def resolve(organization_id) when is_integer(organization_id) do
    Configurations.get_or_create_configuration("Organization", organization_id, "organization")

    Enum.reduce(@default_policy, %{}, fn {key, default}, acc ->
      value = Configurations.get_setting("Organization", organization_id, key)
      Map.put(acc, key, if(is_nil(value), do: default, else: value))
    end)
  end

  @doc """
  Validates a password against a policy.

  Applies length and complexity validations to the `:password` field of the
  given changeset. Confirmation matching is intentionally left to the caller so
  it can be applied regardless of policy.
  """
  def validate_password(%Ecto.Changeset{} = changeset, policy) do
    changeset
    |> validate_length(policy)
    |> validate_complexity(policy)
  end

  @doc """
  Returns a human-readable list of the requirements imposed by a policy, suitable
  for display in password input hints.
  """
  def describe(policy) do
    [
      "At least #{policy.password_min_length} characters"
    ] ++
      maybe(:uppercase, policy.password_require_uppercase) ++
      maybe(:lowercase, policy.password_require_lowercase) ++
      maybe(:digit, policy.password_require_digit) ++
      maybe(:special, policy.password_require_special)
  end

  defp maybe(_kind, value) when value in [false, nil], do: []

  defp maybe(kind, _value) when kind in [:uppercase, :lowercase, :digit, :special] do
    [
      case kind do
        :uppercase -> "At least one uppercase letter (A-Z)"
        :lowercase -> "At least one lowercase letter (a-z)"
        :digit -> "At least one number (0-9)"
        :special -> "At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)"
      end
    ]
  end

  @doc """
  Generates a random password that satisfies the given policy.
  """
  def generate(policy) do
    required =
      [
        {policy.password_require_uppercase, fn -> random_chars(?A..?Z, 3) end},
        {policy.password_require_lowercase, fn -> random_chars(?a..?z, 3) end},
        {policy.password_require_digit, fn -> random_chars(?0..?9, 3) end},
        {policy.password_require_special, fn -> random_chars(~c"!@#$%^&*", 3) end}
      ]
      |> Enum.flat_map(fn {enabled, generator} ->
        if enabled, do: [generator.()], else: []
      end)

    min_length = max(policy.password_min_length, length(required))

    padding =
      random_chars(valid_character_set(policy), max(0, min_length - length(required)))

    (required ++ [padding])
    |> Enum.join()
    |> String.graphemes()
    |> Enum.shuffle()
    |> Enum.join()
  end

  defp validate_length(changeset, policy) do
    Ecto.Changeset.validate_length(changeset, :password,
      min: policy.password_min_length,
      max: policy.password_max_length,
      message:
        "must be between #{policy.password_min_length} and #{policy.password_max_length} characters"
    )
  end

  defp validate_complexity(changeset, policy) do
    case Ecto.Changeset.get_change(changeset, :password) do
      nil ->
        changeset

      password when is_binary(password) ->
        changeset
        |> maybe_require_uppercase(password, policy)
        |> maybe_require_lowercase(password, policy)
        |> maybe_require_digit(password, policy)
        |> maybe_require_special(password, policy)
        |> maybe_block_common(password, policy)

      _ ->
        changeset
    end
  end

  defp maybe_require_uppercase(changeset, _password, %{password_require_uppercase: false}) do
    changeset
  end

  defp maybe_require_uppercase(changeset, password, _policy) do
    if Regex.match?(~r/[A-Z]/, password) do
      changeset
    else
      Ecto.Changeset.add_error(changeset, :password, "must contain at least one uppercase letter")
    end
  end

  defp maybe_require_lowercase(changeset, _password, %{password_require_lowercase: false}) do
    changeset
  end

  defp maybe_require_lowercase(changeset, password, _policy) do
    if Regex.match?(~r/[a-z]/, password) do
      changeset
    else
      Ecto.Changeset.add_error(changeset, :password, "must contain at least one lowercase letter")
    end
  end

  defp maybe_require_digit(changeset, _password, %{password_require_digit: false}) do
    changeset
  end

  defp maybe_require_digit(changeset, password, _policy) do
    if Regex.match?(~r/[0-9]/, password) do
      changeset
    else
      Ecto.Changeset.add_error(changeset, :password, "must contain at least one number")
    end
  end

  defp maybe_require_special(changeset, _password, %{password_require_special: false}) do
    changeset
  end

  defp maybe_require_special(changeset, password, _policy) do
    if Regex.match?(~r/[^A-Za-z0-9]/, password) do
      changeset
    else
      Ecto.Changeset.add_error(
        changeset,
        :password,
        "must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)"
      )
    end
  end

  defp maybe_block_common(changeset, _password, %{password_common_blocklist_enabled: false}) do
    changeset
  end

  defp maybe_block_common(changeset, password, _policy) do
    if String.downcase(password) in @common_passwords do
      Ecto.Changeset.add_error(
        changeset,
        :password,
        "is too common, please choose a more secure password"
      )
    else
      changeset
    end
  end

  defp random_chars(range_or_list, count) do
    Enum.take_random(range_or_list, count)
    |> List.to_string()
  end

  defp valid_character_set(policy) do
    set =
      %{}
      |> then(fn set ->
        if policy.password_require_uppercase, do: Map.put(set, :upper, ?A..?Z), else: set
      end)
      |> then(fn set ->
        if policy.password_require_lowercase, do: Map.put(set, :lower, ?a..?z), else: set
      end)
      |> then(fn set ->
        if policy.password_require_digit, do: Map.put(set, :digit, ?0..?9), else: set
      end)
      |> then(fn set ->
        if policy.password_require_special, do: Map.put(set, :special, ~c"!@#$%^&*"), else: set
      end)
      |> Map.values()
      |> Enum.flat_map(&Enum.to_list/1)

    # Always guarantee at least a usable charset so the generated password is
    # never empty, even when every character class is disabled.
    if set == [], do: Enum.to_list(?a..?z), else: set
  end
end
