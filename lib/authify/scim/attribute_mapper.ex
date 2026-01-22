defmodule Authify.SCIM.AttributeMapper do
  @moduledoc """
  Maps SCIM attribute names to Authify database fields and vice versa.

  This module provides secure attribute name resolution to prevent atom exhaustion
  attacks when processing untrusted SCIM filter expressions.

  ## Security

  Uses an allowlist approach with `String.to_existing_atom/1` to prevent creation
  of arbitrary atoms from user input, which could exhaust the atom table.

  ## Examples

      iex> scim_to_ecto_field("userName", :user)
      {:ok, :username}

      iex> scim_to_ecto_field("name.givenName", :user)
      {:ok, :first_name}

      iex> scim_to_ecto_field("invalid_field", :user)
      {:error, :unknown_attribute}
  """

  # User attribute mappings (SCIM → Ecto)
  @user_scim_to_ecto %{
    "id" => :id,
    "externalId" => :external_id,
    "userName" => :username,
    "name.givenName" => :first_name,
    "name.familyName" => :last_name,
    "emails" => :email,
    "emails.value" => :email,
    "active" => :active,
    "meta.created" => :scim_created_at,
    "meta.lastModified" => :scim_updated_at
  }

  # Group attribute mappings (SCIM → Ecto)
  @group_scim_to_ecto %{
    "id" => :id,
    "externalId" => :external_id,
    "displayName" => :name,
    "meta.created" => :scim_created_at,
    "meta.lastModified" => :scim_updated_at
  }

  # Reverse mappings for response formatting
  @user_ecto_to_scim Enum.into(@user_scim_to_ecto, %{}, fn {k, v} -> {v, k} end)
  @group_ecto_to_scim Enum.into(@group_scim_to_ecto, %{}, fn {k, v} -> {v, k} end)

  @doc """
  Converts a SCIM attribute path to an Ecto field atom.

  Returns `{:ok, field_atom}` if the attribute is known, or
  `{:error, :unknown_attribute}` if not in the allowlist.

  ## Parameters
    * `scim_path` - SCIM attribute path (e.g., "userName", "name.givenName")
    * `resource_type` - Either `:user` or `:group`

  ## Examples

      iex> scim_to_ecto_field("userName", :user)
      {:ok, :username}

      iex> scim_to_ecto_field("displayName", :group)
      {:ok, :name}
  """
  def scim_to_ecto_field(scim_path, :user) when is_binary(scim_path) do
    case Map.get(@user_scim_to_ecto, scim_path) do
      nil -> {:error, :unknown_attribute}
      field -> {:ok, field}
    end
  end

  def scim_to_ecto_field(scim_path, :group) when is_binary(scim_path) do
    case Map.get(@group_scim_to_ecto, scim_path) do
      nil -> {:error, :unknown_attribute}
      field -> {:ok, field}
    end
  end

  @doc """
  Converts an Ecto field atom to a SCIM attribute path.

  Returns the SCIM attribute name or the original field name if not mapped.

  ## Examples

      iex> ecto_to_scim_attribute(:username, :user)
      "userName"

      iex> ecto_to_scim_attribute(:first_name, :user)
      "name.givenName"
  """
  def ecto_to_scim_attribute(field, :user) when is_atom(field) do
    Map.get(@user_ecto_to_scim, field, Atom.to_string(field))
  end

  def ecto_to_scim_attribute(field, :group) when is_atom(field) do
    Map.get(@group_ecto_to_scim, field, Atom.to_string(field))
  end

  @doc """
  Returns all known SCIM attribute names for a resource type.

  Useful for validation and error messages.

  ## Examples

      iex> known_scim_attributes(:user)
      ["id", "externalId", "userName", "name.givenName", ...]
  """
  def known_scim_attributes(:user), do: Map.keys(@user_scim_to_ecto)
  def known_scim_attributes(:group), do: Map.keys(@group_scim_to_ecto)

  @doc """
  Checks if a SCIM attribute is valid for the resource type.

  ## Examples

      iex> valid_scim_attribute?("userName", :user)
      true

      iex> valid_scim_attribute?("invalidField", :user)
      false
  """
  def valid_scim_attribute?(scim_path, resource_type) do
    case scim_to_ecto_field(scim_path, resource_type) do
      {:ok, _} -> true
      {:error, _} -> false
    end
  end
end
