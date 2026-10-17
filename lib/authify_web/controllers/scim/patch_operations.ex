defmodule AuthifyWeb.SCIM.PatchOperations do
  @moduledoc """
  Shared PATCH operation logic for SCIM resources (Users and Groups).

  Implements RFC 7644 Section 3.5.2 PATCH operations:

  - `add`: adds a new attribute value. For single-valued attributes this has
    upsert semantics (matching the behavior of Microsoft Entra ID).
  - `remove`: removes a value from an attribute.
  - `replace`: replaces an existing attribute value.

  User PATCH supports the scalar attributes `active`, `name.givenName`,
  `name.familyName`, `title`, and `phoneNumbers.value`, plus the multi-valued
  `emails` attribute. Multi-valued attributes accept value-selector paths such
  as `emails[type eq "work"].value`.
  """

  alias Authify.Accounts
  alias Authify.Groups
  alias Authify.Repo
  alias Authify.SCIM.{FilterParser, Provisioning}
  alias AuthifyWeb.SCIM.{Helpers, Mappers}

  # SCIM user attribute paths that map to a single (scalar) Ecto field.
  @user_scalar_fields %{
    "active" => :active,
    "name.givenname" => :first_name,
    "name.familyname" => :last_name,
    "title" => :title,
    "phonenumbers.value" => :phone_number
  }

  # Attributes that must not be removed entirely (RFC 7643 required fields).
  @user_unremovable_paths ~w(active username emails emails.value)

  # Sub-attributes that may be set on an email entry via a selector path.
  @email_sub_attributes ~w(value type primary display)

  @doc """
  Applies a list of PATCH operations to a user resource.

  Returns {:ok, updated_user} or {:error, reason}.
  """
  def apply_user_patch_operations(user, operations) do
    user = Repo.preload(user, :emails, force: true)

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

  defp apply_single_user_patch_op(user, operation) do
    user
    |> do_apply_user_patch_op(operation)
    |> normalize_result()
  end

  defp do_apply_user_patch_op(user, %{"op" => raw_op} = operation) do
    op = normalize_op(raw_op)
    path = operation["path"]
    value = operation["value"]

    cond do
      op in [:add, :replace] -> apply_user_add_or_replace(user, path, value, op)
      op == :remove -> apply_user_remove(user, path)
      true -> {:error, "Unsupported PATCH operation: #{raw_op}"}
    end
  end

  defp do_apply_user_patch_op(_user, operation) do
    {:error, "Unsupported PATCH operation: #{inspect(operation["op"])}"}
  end

  # `add`/`replace` with no path and a map value updates the whole resource.
  defp apply_user_add_or_replace(user, nil, value, _op) when is_map(value) do
    apply_user_resource_map(user, value)
  end

  defp apply_user_add_or_replace(user, path, value, op) when is_binary(path) do
    case FilterParser.parse_attribute_path(path) do
      {:ok, {:simple, "emails"}} ->
        apply_user_emails(user, op, nil, nil, value)

      {:ok, {:simple, "emails.value"}} ->
        apply_user_emails(user, op, "value", nil, value)

      {:ok, {:simple, simple}} ->
        apply_user_scalar(user, simple, value, path)

      {:ok, {:filtered, "emails", sub_attribute, selector}} ->
        apply_user_emails(user, op, sub_attribute, selector, value)

      {:ok, {:filtered, _attribute, _sub_attribute, _selector}} ->
        {:error, "Unsupported PATCH path: #{path}"}

      {:error, reason} ->
        {:error, "Invalid PATCH path #{path}: #{reason}"}
    end
  end

  defp apply_user_add_or_replace(_user, path, _value, _op) do
    {:error, "Invalid PATCH path: #{inspect(path)}"}
  end

  # No-path map value: update scalar attributes and, when emails are supplied,
  # the email collection too.
  defp apply_user_resource_map(user, value) do
    attrs = value |> Mappers.map_user_attrs() |> Map.delete(:emails)

    case Provisioning.update_user_scim(user, attrs) do
      {:ok, updated_user} ->
        if Map.has_key?(value, "emails") do
          persist_emails(updated_user, value_to_entries(value["emails"]))
        else
          {:ok, updated_user}
        end

      error ->
        error
    end
  end

  defp apply_user_scalar(user, "active", value, _path) do
    case coerce_boolean(value) do
      {:ok, active} -> Provisioning.update_user_scim(user, %{active: active})
      {:error, reason} -> {:error, reason}
    end
  end

  defp apply_user_scalar(user, simple, value, path) do
    case Map.fetch(@user_scalar_fields, simple) do
      {:ok, field} -> Provisioning.update_user_scim(user, %{field => value})
      :error -> {:error, "Unsupported PATCH path: #{path}"}
    end
  end

  defp apply_user_remove(user, path) when is_binary(path) do
    case FilterParser.parse_attribute_path(path) do
      {:ok, {:simple, simple}} ->
        cond do
          simple in @user_unremovable_paths ->
            {:error, "Cannot remove required attribute: #{path}"}

          Map.has_key?(@user_scalar_fields, simple) ->
            {:ok, field} = Map.fetch(@user_scalar_fields, simple)
            Provisioning.update_user_scim(user, %{field => nil})

          true ->
            {:error, "Unsupported PATCH path: #{path}"}
        end

      {:ok, {:filtered, "emails", _sub_attribute, selector}} ->
        apply_user_emails(user, :remove, nil, selector, nil)

      {:ok, {:filtered, _attribute, _sub_attribute, _selector}} ->
        {:error, "Unsupported PATCH path: #{path}"}

      {:error, reason} ->
        {:error, "Invalid PATCH path #{path}: #{reason}"}
    end
  end

  defp apply_user_remove(_user, path) do
    {:error, "Invalid PATCH path: #{inspect(path)}"}
  end

  # Multi-valued `emails` operations

  defp apply_user_emails(user, :remove, _sub_attribute, selector, _value) do
    current = current_email_maps(user)
    remaining = Enum.reject(current, &FilterParser.matches?(&1, selector))

    cond do
      length(remaining) == length(current) -> {:ok, user}
      remaining == [] -> {:error, "Cannot remove all email addresses from a user"}
      true -> persist_emails(user, remaining)
    end
  end

  defp apply_user_emails(user, op, sub_attribute, selector, value) when op in [:add, :replace] do
    current = current_email_maps(user)

    case build_email_change(current, op, sub_attribute, selector, value) do
      {:ok, desired} -> persist_emails(user, desired)
      {:error, reason} -> {:error, reason}
    end
  end

  defp build_email_change(current, op, sub_attribute, selector, value) do
    cond do
      not is_nil(selector) ->
        apply_email_selector_change(current, selector, sub_attribute, value)

      sub_attribute == "value" and is_binary(value) ->
        update_primary_email_value(current, value)

      true ->
        entries = value_to_entries(value)

        case op do
          :replace -> {:ok, entries}
          :add -> {:ok, merge_emails(current, entries)}
        end
    end
  end

  defp update_primary_email_value(current, value) do
    case Enum.find_index(current, & &1["primary"]) do
      nil -> {:error, "Cannot update email value: no primary email found"}
      index -> {:ok, List.update_at(current, index, &Map.put(&1, "value", value))}
    end
  end

  defp apply_email_selector_change(current, selector, sub_attribute, value) do
    if Enum.any?(current, &FilterParser.matches?(&1, selector)) do
      if valid_email_entry_change?(sub_attribute, value) do
        {:ok,
         Enum.map(current, fn entry ->
           if FilterParser.matches?(entry, selector) do
             apply_email_entry_change(entry, sub_attribute, value)
           else
             entry
           end
         end)}
      else
        {:error, "Unsupported PATCH value for email selector"}
      end
    else
      case new_email_from_selector(selector, sub_attribute, value) do
        {:ok, entry} -> {:ok, current ++ [entry]}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp valid_email_entry_change?(sub_attribute, value) do
    cond do
      is_map(value) -> true
      is_nil(sub_attribute) -> is_binary(value)
      sub_attribute in @email_sub_attributes -> not is_list(value)
      true -> false
    end
  end

  defp apply_email_entry_change(entry, _sub_attribute, value) when is_map(value) do
    merge_email(entry, normalize_email_entry(value))
  end

  defp apply_email_entry_change(entry, nil, value) do
    Map.put(entry, "value", value)
  end

  defp apply_email_entry_change(entry, sub_attribute, value) do
    Map.put(entry, sub_attribute, value)
  end

  defp new_email_from_selector(selector, sub_attribute, value) do
    base =
      %{"value" => nil, "type" => "work", "primary" => false, "display" => nil}
      |> seed_email_from_selector(selector)

    entry =
      cond do
        is_map(value) -> merge_email(base, normalize_email_entry(value))
        is_binary(sub_attribute) -> Map.put(base, sub_attribute, value)
        true -> Map.put(base, "value", value)
      end

    if is_binary(entry["value"]) and entry["value"] != "" do
      {:ok, entry}
    else
      {:error, "Cannot add an email without a value"}
    end
  end

  defp seed_email_from_selector(entry, {:and, left, right}) do
    entry |> seed_email_from_selector(left) |> seed_email_from_selector(right)
  end

  defp seed_email_from_selector(entry, {:eq, attribute, value}) do
    key = String.downcase(to_string(attribute))

    if key in @email_sub_attributes do
      Map.put(entry, key, value)
    else
      entry
    end
  end

  defp seed_email_from_selector(entry, _ast), do: entry

  defp merge_emails(current, entries) do
    Enum.reduce(entries, current, fn entry, acc ->
      key = normalize_email_value(entry["value"])

      case Enum.find_index(acc, &(normalize_email_value(&1["value"]) == key)) do
        nil ->
          acc ++ [entry]

        index ->
          merged = acc |> Enum.at(index) |> merge_email(entry)
          List.replace_at(acc, index, merged)
      end
    end)
  end

  defp merge_email(existing, incoming) do
    existing
    |> put_email_field("type", incoming["type"])
    |> put_email_field("primary", incoming["primary"])
    |> put_email_field("display", incoming["display"])
  end

  defp put_email_field(entry, _key, nil), do: entry
  defp put_email_field(entry, key, value), do: Map.put(entry, key, value)

  defp current_email_maps(user) do
    user = Repo.preload(user, :emails, force: true)

    Enum.map(user.emails, fn email ->
      %{
        "value" => email.value,
        "type" => email.type,
        "primary" => email.primary,
        "display" => email.display
      }
    end)
  end

  defp value_to_entries(value) when is_list(value), do: Enum.map(value, &normalize_email_entry/1)
  defp value_to_entries(value), do: [normalize_email_entry(value)]

  defp normalize_email_entry(%{} = entry) do
    %{
      "value" => entry["value"] || entry[:value],
      "type" => entry["type"] || entry[:type] || "work",
      "primary" => entry["primary"] || entry[:primary] || false,
      "display" => entry["display"] || entry[:display]
    }
  end

  defp normalize_email_entry(value) when is_binary(value) do
    %{"value" => value, "type" => "work", "primary" => false, "display" => nil}
  end

  defp normalize_email_entry(_value) do
    %{"value" => nil, "type" => "work", "primary" => false, "display" => nil}
  end

  defp persist_emails(user, desired) do
    case Provisioning.update_user_emails_scim(user, desired) do
      {:ok, updated_user} ->
        {:ok, updated_user}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:error, Helpers.format_changeset_errors(changeset)}

      {:error, reason} ->
        {:error, error_message(reason)}
    end
  end

  defp normalize_email_value(value) when is_binary(value) do
    value |> String.trim() |> String.downcase()
  end

  defp normalize_email_value(value), do: value

  defp coerce_boolean(true), do: {:ok, true}
  defp coerce_boolean(false), do: {:ok, false}
  defp coerce_boolean(1), do: {:ok, true}
  defp coerce_boolean(0), do: {:ok, false}

  defp coerce_boolean(value) when is_binary(value) do
    case value |> String.trim() |> String.downcase() do
      "true" -> {:ok, true}
      "false" -> {:ok, false}
      "1" -> {:ok, true}
      "0" -> {:ok, false}
      _ -> {:error, "Invalid boolean value for active: #{inspect(value)}"}
    end
  end

  defp coerce_boolean(value), do: {:error, "Invalid boolean value for active: #{inspect(value)}"}

  defp normalize_op(op) when is_binary(op) do
    case String.downcase(op) do
      "add" -> :add
      "remove" -> :remove
      "replace" -> :replace
      other -> other
    end
  end

  defp normalize_op(op), do: op

  defp normalize_result({:error, %Ecto.Changeset{} = changeset}) do
    {:error, Helpers.format_changeset_errors(changeset)}
  end

  defp normalize_result(result), do: result

  defp error_message(reason) when is_binary(reason), do: reason
  defp error_message(reason), do: inspect(reason)

  # Private functions for group PATCH operations

  defp apply_single_group_patch_op(
         group,
         %{"op" => "replace", "path" => path, "value" => value},
         _organization
       ) do
    case normalize_path(path) do
      "displayname" ->
        Provisioning.update_group_scim(group, %{name: value})

      _ ->
        {:error, "Unsupported PATCH path: #{path}"}
    end
  end

  defp apply_single_group_patch_op(group, %{"op" => "replace", "value" => value}, _organization)
       when is_map(value) do
    # Replace operation with no path - update entire resource
    attrs = Mappers.map_group_attrs(value)
    Provisioning.update_group_scim(group, attrs)
  end

  defp apply_single_group_patch_op(
         group,
         %{"op" => "add", "path" => "members", "value" => members},
         organization
       )
       when is_list(members) do
    # Add members to the group
    case add_members_to_group(group, members, organization) do
      :ok -> {:ok, Repo.preload(group, :users, force: true)}
      {:error, reason} -> {:error, reason}
    end
  end

  defp apply_single_group_patch_op(group, %{"op" => "remove", "path" => path}, organization) do
    # Remove members from the group
    # Path format: members[value eq "user-id"]
    case parse_member_filter(path) do
      {:ok, user_id} ->
        case remove_member_from_group(group, user_id, organization) do
          :ok -> {:ok, Repo.preload(group, :users, force: true)}
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
              case Groups.add_user_to_group(user, group) do
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
            Groups.remove_user_from_group(user, group)
            :ok

          {:error, :not_found} ->
            {:error, "User not found: #{user_id}"}
        end
    end
  end

  defp parse_member_filter(path) do
    # Parse: members[value eq "user-id"]
    case FilterParser.parse_attribute_path(path) do
      {:ok, {:filtered, "members", nil, {:eq, "value", user_id}}} ->
        {:ok, user_id}

      _ ->
        {:error, "Invalid member filter path: #{path}"}
    end
  end
end
