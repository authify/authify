defmodule AuthifyWeb.SCIM.PatchOperations do
  @moduledoc """
  Shared PATCH operation logic for SCIM resources (Users and Groups).

  Implements RFC 7644 Section 3.5.2 PATCH operations:
  - add: adds a new attribute value
  - remove: removes a value from an attribute
  - replace: replaces an existing attribute value
  """

  alias Authify.Accounts
  alias AuthifyWeb.SCIM.{Helpers, Mappers}

  @doc """
  Applies a list of PATCH operations to a user resource.

  Returns {:ok, updated_user} or {:error, reason}.
  """
  def apply_user_patch_operations(user, operations) do
    Enum.reduce_while(operations, {:ok, user}, fn op, {:ok, current_user} ->
      case apply_single_user_patch_op(current_user, op) do
        {:ok, updated_user} -> {:cont, {:ok, updated_user}}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  @doc """
  Applies a list of PATCH operations to a group resource.

  Returns {:ok, updated_group} or {:error, reason}.
  """
  def apply_group_patch_operations(group, operations, organization) do
    Enum.reduce_while(operations, {:ok, group}, fn op, {:ok, current_group} ->
      case apply_single_group_patch_op(current_group, op, organization) do
        {:ok, updated_group} -> {:cont, {:ok, updated_group}}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  # Private functions for user PATCH operations

  defp apply_single_user_patch_op(user, %{"op" => "replace", "path" => path, "value" => value}) do
    case normalize_path(path) do
      "active" ->
        Accounts.update_user_scim(user, %{active: value})

      "name.givenname" ->
        Accounts.update_user_scim(user, %{first_name: value})

      "name.familyname" ->
        Accounts.update_user_scim(user, %{last_name: value})

      _ ->
        {:error, "Unsupported PATCH path: #{path}"}
    end
  end

  defp apply_single_user_patch_op(user, %{"op" => "replace", "value" => value})
       when is_map(value) do
    # Replace operation with no path - update entire resource
    attrs = Mappers.map_user_attrs(value)
    Accounts.update_user_scim(user, attrs)
  end

  defp apply_single_user_patch_op(_user, op) do
    {:error, "Unsupported PATCH operation: #{op["op"]}"}
  end

  # Private functions for group PATCH operations

  defp apply_single_group_patch_op(
         group,
         %{"op" => "replace", "path" => path, "value" => value},
         _organization
       ) do
    case normalize_path(path) do
      "displayname" ->
        Accounts.update_group_scim(group, %{name: value})

      _ ->
        {:error, "Unsupported PATCH path: #{path}"}
    end
  end

  defp apply_single_group_patch_op(group, %{"op" => "replace", "value" => value}, _organization)
       when is_map(value) do
    # Replace operation with no path - update entire resource
    attrs = Mappers.map_group_attrs(value)
    Accounts.update_group_scim(group, attrs)
  end

  defp apply_single_group_patch_op(
         group,
         %{"op" => "add", "path" => "members", "value" => members},
         organization
       )
       when is_list(members) do
    # Add members to the group
    case add_members_to_group(group, members, organization) do
      :ok -> {:ok, Authify.Repo.preload(group, :users, force: true)}
      {:error, reason} -> {:error, reason}
    end
  end

  defp apply_single_group_patch_op(group, %{"op" => "remove", "path" => path}, organization) do
    # Remove members from the group
    # Path format: members[value eq "user-id"]
    case parse_member_filter(path) do
      {:ok, user_id} ->
        case remove_member_from_group(group, user_id, organization) do
          :ok -> {:ok, Authify.Repo.preload(group, :users, force: true)}
          {:error, reason} -> {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp apply_single_group_patch_op(_group, op, _organization) do
    {:error, "Unsupported PATCH operation: #{op["op"]}"}
  end

  # Shared helper functions

  defp normalize_path(nil), do: nil
  defp normalize_path(path) when is_binary(path), do: String.downcase(path)

  defp add_members_to_group(group, members, organization) do
    Enum.reduce_while(members, :ok, fn member, :ok ->
      user_id = member["value"]

      case Accounts.get_user(user_id) do
        nil ->
          {:halt, {:error, "User with id '#{user_id}' not found"}}

        user ->
          case Helpers.validate_resource_organization(user, organization) do
            :ok ->
              case Accounts.add_user_to_group(user, group) do
                {:ok, _} -> {:cont, :ok}
                # Already a member, ignore
                {:error, %Ecto.Changeset{}} -> {:cont, :ok}
                {:error, reason} -> {:halt, {:error, "Failed to add member: #{inspect(reason)}"}}
              end

            {:error, :not_found} ->
              {:halt, {:error, "User '#{user_id}' does not belong to this organization"}}
          end
      end
    end)
  end

  defp remove_member_from_group(group, user_id, organization) do
    case Accounts.get_user(user_id) do
      nil ->
        {:error, "User not found: #{user_id}"}

      user ->
        case Helpers.validate_resource_organization(user, organization) do
          :ok ->
            Accounts.remove_user_from_group(user, group)
            :ok

          {:error, :not_found} ->
            {:error, "User not found: #{user_id}"}
        end
    end
  end

  defp parse_member_filter(path) do
    # Parse: members[value eq "user-id"]
    case Regex.run(~r/members\[value eq "(.+?)"\]/i, path) do
      [_, user_id] -> {:ok, user_id}
      _ -> {:error, "Invalid member filter path: #{path}"}
    end
  end
end
