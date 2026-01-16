defmodule Authify.AccountsFixtures do
  @moduledoc """
  This module defines test helpers for creating
  entities via the `Authify.Accounts` context.
  """

  alias Authify.Accounts

  @doc """
  Generate a unique organization name.
  """
  def unique_organization_name, do: "Test Organization #{System.unique_integer()}"

  @doc """
  Generate a unique organization slug.
  """
  def unique_organization_slug, do: "test-org-#{System.unique_integer()}"

  @doc """
  Generate a unique user email.
  """
  def unique_user_email, do: "user#{System.unique_integer()}@example.com"

  def unique_user_username, do: "testuser#{System.unique_integer()}"

  @doc """
  Generate a unique organization domain.
  """
  def unique_organization_domain, do: "example#{System.unique_integer()}.com"

  @doc """
  Generate an organization.
  """
  def organization_fixture(attrs \\ %{}) do
    {:ok, organization} =
      attrs
      |> Enum.into(%{
        name: unique_organization_name(),
        slug: unique_organization_slug(),
        domain: unique_organization_domain()
      })
      |> Accounts.create_organization()

    organization
  end

  @doc """
  Generate a user.
  """
  def user_fixture(attrs \\ %{}) do
    # Convert to map if it's a keyword list
    attrs = if is_list(attrs), do: Enum.into(attrs, %{}), else: attrs

    # Extract organization and role from attrs or use defaults
    organization = Map.get(attrs, :organization) || organization_fixture()
    role = Map.get(attrs, :role) || Map.get(attrs, "role") || "user"

    # Remove organization and role from attrs to avoid mixed keys
    user_attrs = Map.drop(attrs, [:organization, :role, "role"])

    # Convert atom keys to string keys to avoid mixed key maps
    user_attrs =
      user_attrs
      |> Enum.map(fn
        {k, v} when is_atom(k) -> {Atom.to_string(k), v}
        {k, v} -> {k, v}
      end)
      |> Enum.into(%{})

    # Generate email if not provided in nested format
    email_value = Map.get(user_attrs, "email") || unique_user_email()

    # Remove old email key and add emails association
    user_attrs = Map.drop(user_attrs, ["email"])

    emails =
      Map.get(user_attrs, "emails") ||
        [
          %{
            "value" => email_value,
            "type" => "work",
            "primary" => true
          }
        ]

    {:ok, user} =
      user_attrs
      |> Enum.into(%{
        "first_name" => "Test",
        "last_name" => "User",
        "emails" => emails,
        "username" => unique_user_username(),
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      })
      |> Accounts.create_user_with_role(organization.id, role)

    # Return user with organization and emails preloaded
    Accounts.get_user!(user.id)
  end

  @doc """
  Generate a user for a specific organization.
  """
  def user_for_organization_fixture(organization, attrs \\ %{}) do
    # Extract role from attrs before passing to user creation
    role = Map.get(attrs, :role) || Map.get(attrs, "role") || "user"
    user_attrs = Map.drop(attrs, [:role, "role"])

    # Generate email if not provided in nested format
    email_value = Map.get(user_attrs, "email") || unique_user_email()

    # Remove old email key and add emails association
    user_attrs = Map.drop(user_attrs, ["email"])

    emails =
      Map.get(user_attrs, "emails") ||
        [
          %{
            "value" => email_value,
            "type" => "work",
            "primary" => true
          }
        ]

    {:ok, user} =
      user_attrs
      |> Enum.into(%{
        "first_name" => "Test",
        "last_name" => "User",
        "emails" => emails,
        "username" => unique_user_username(),
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      })
      |> Accounts.create_user_with_role(organization.id, role)

    # Return user with organization and emails preloaded
    Accounts.get_user!(user.id)
  end

  @doc """
  Generate an admin user for a specific organization.
  """
  def admin_user_fixture(organization, attrs \\ %{}) do
    # Generate email if not provided in nested format
    email_value = Map.get(attrs, "email") || unique_user_email()

    # Remove old email key and add emails association
    attrs = Map.drop(attrs, ["email"])

    emails =
      Map.get(attrs, "emails") ||
        [
          %{
            "value" => email_value,
            "type" => "work",
            "primary" => true
          }
        ]

    {:ok, user} =
      attrs
      |> Enum.into(%{
        "first_name" => "Admin",
        "last_name" => "User",
        "emails" => emails,
        "username" => unique_user_username(),
        "password" => "SecureP@ssw0rd!",
        "password_confirmation" => "SecureP@ssw0rd!"
      })
      |> Accounts.create_user_with_role(organization.id, "admin")

    # Return user with organization and emails preloaded
    Accounts.get_user!(user.id)
  end

  @doc """
  Generate an invitation.
  """
  def invitation_fixture(attrs \\ %{}) do
    organization = organization_fixture()
    inviter = admin_user_fixture(organization)

    {:ok, invitation} =
      attrs
      |> Enum.into(%{
        "email" => unique_user_email(),
        "role" => "user",
        "organization_id" => organization.id,
        "invited_by_id" => inviter.id
      })
      |> Accounts.create_invitation()

    invitation
  end

  @doc """
  Generate an invitation for a specific organization and inviter.
  """
  def invitation_for_organization_fixture(organization, inviter, attrs \\ %{}) do
    {:ok, invitation} =
      attrs
      |> Enum.into(%{
        "email" => unique_user_email(),
        "role" => "user",
        "organization_id" => organization.id,
        "invited_by_id" => inviter.id
      })
      |> Accounts.create_invitation()

    invitation
  end

  @doc """
  Generate a unique group name.
  """
  def unique_group_name, do: "Test Group #{System.unique_integer()}"

  @doc """
  Generate a group.
  """
  def group_fixture(attrs \\ %{}) do
    # Convert to map if it's a keyword list
    attrs = if is_list(attrs), do: Enum.into(attrs, %{}), else: attrs

    # Extract organization from attrs or use default
    organization = Map.get(attrs, :organization) || organization_fixture()

    # Remove organization from attrs to avoid mixed keys
    group_attrs = Map.drop(attrs, [:organization])

    # Convert atom keys to string keys to avoid mixed key maps
    group_attrs =
      group_attrs
      |> Enum.map(fn
        {k, v} when is_atom(k) -> {Atom.to_string(k), v}
        {k, v} -> {k, v}
      end)
      |> Enum.into(%{})

    {:ok, group} =
      group_attrs
      |> Enum.into(%{
        "name" => unique_group_name(),
        "organization_id" => organization.id
      })
      |> Accounts.create_group()

    # Return group with organization preloaded
    Accounts.get_group!(group.id, organization)
  end
end
