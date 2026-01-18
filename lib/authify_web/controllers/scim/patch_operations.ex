defmodule AuthifyWeb.SCIM.PatchOperations do
  @moduledoc """
  Shared PATCH operation logic for SCIM resources (Users and Groups).

  Implements RFC 7644 Section 3.5.2 PATCH operations:
  - add: adds a new attribute value
  - remove: removes a value from an attribute
  - replace: replaces an existing attribute value
  """

  alias Authify.Accounts

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
    attrs = map_scim_to_user_attrs(value)
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
    attrs = map_scim_to_group_attrs(value)
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
          if user.organization_id == organization.id do
            case Accounts.add_user_to_group(user, group) do
              {:ok, _} -> {:cont, :ok}
              # Already a member, ignore
              {:error, %Ecto.Changeset{}} -> {:cont, :ok}
              {:error, reason} -> {:halt, {:error, "Failed to add member: #{inspect(reason)}"}}
            end
          else
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
        if user.organization_id == organization.id do
          Accounts.remove_user_from_group(user, group)
          :ok
        else
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

  # Map SCIM user attributes (duplicated from UsersController for now)
  defp map_scim_to_user_attrs(params) when is_map(params) do
    {attrs, username_email} = map_username_field(params)

    attrs
    |> maybe_put(:external_id, params["externalId"])
    |> maybe_put(:first_name, get_in(params, ["name", "givenName"]))
    |> maybe_put(:last_name, get_in(params, ["name", "familyName"]))
    |> maybe_put(:active, params["active"])
    |> Map.put(:emails, build_email_list(params, username_email))
  end

  defp map_scim_to_user_attrs(_), do: %{}

  defp map_username_field(params) do
    case params["userName"] do
      nil ->
        {%{}, nil}

      username when is_binary(username) ->
        if String.contains?(username, "@") do
          {%{}, username}
        else
          {%{username: username}, nil}
        end
    end
  end

  defp build_email_list(params, username_email) do
    cond do
      params["emails"] && is_list(params["emails"]) ->
        params["emails"]
        |> Enum.map(&convert_scim_email/1)
        |> ensure_primary_email()

      username_email ->
        [%{"value" => username_email, "type" => "work", "primary" => true}]

      true ->
        []
    end
  end

  defp convert_scim_email(email) do
    %{
      "value" => Map.get(email, "value"),
      "type" => Map.get(email, "type", "work"),
      "primary" => Map.get(email, "primary", false),
      "display" => Map.get(email, "display")
    }
  end

  defp ensure_primary_email(emails) do
    if Enum.any?(emails, & &1["primary"]) do
      emails
    else
      case emails do
        [first | rest] -> [Map.put(first, "primary", true) | rest]
        [] -> []
      end
    end
  end

  # Map SCIM group attributes (duplicated from GroupsController for now)
  defp map_scim_to_group_attrs(params) when is_map(params) do
    %{}
    |> maybe_put(:name, params["displayName"])
    |> maybe_put(:external_id, params["externalId"])
  end

  defp map_scim_to_group_attrs(_), do: %{}

  defp maybe_put(attrs, _key, nil), do: attrs
  defp maybe_put(attrs, key, value), do: Map.put(attrs, key, value)
end
