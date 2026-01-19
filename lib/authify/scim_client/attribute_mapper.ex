defmodule Authify.SCIMClient.AttributeMapper do
  @moduledoc """
  Maps Authify resources to SCIM payloads using configurable templates.
  Supports template interpolation with {{field}} syntax.
  """

  alias Authify.Accounts.{Group, User}

  @doc """
  Maps an Authify user to a SCIM user payload using the provided mapping template.
  """
  def map_user(%User{} = user, mapping) when is_map(mapping) do
    data = %{
      "username" => user.username,
      "first_name" => user.first_name || "",
      "last_name" => user.last_name || "",
      "primary_email" => get_primary_email(user),
      "all_emails" => get_all_emails(user),
      "active" => to_string(user.active),
      "external_id" => user.external_id || ""
    }

    interpolate_template(mapping, data)
  end

  @doc """
  Maps an Authify group to a SCIM group payload using the provided mapping template.
  """
  def map_group(%Group{} = group, mapping) when is_map(mapping) do
    data = %{
      "name" => group.name,
      "description" => group.description || "",
      "external_id" => group.external_id || "",
      "member_ids" => get_member_external_ids(group)
    }

    interpolate_template(mapping, data)
  end

  # Private functions

  defp interpolate_template(template, data) when is_map(template) do
    template
    |> Enum.map(fn {key, value} ->
      {key, interpolate_value(value, data)}
    end)
    |> Enum.into(%{})
  end

  defp interpolate_value(value, data) when is_binary(value) do
    # Replace {{field}} with actual data
    Regex.replace(~r/\{\{(\w+)\}\}/, value, fn _, field ->
      Map.get(data, field, "")
    end)
  end

  defp interpolate_value(value, data) when is_map(value) do
    interpolate_template(value, data)
  end

  defp interpolate_value(value, data) when is_list(value) do
    Enum.map(value, &interpolate_value(&1, data))
  end

  defp interpolate_value(value, _data), do: value

  defp get_primary_email(%User{emails: emails}) when is_list(emails) do
    case Enum.find(emails, & &1.primary) do
      nil -> ""
      email -> email.value
    end
  end

  defp get_primary_email(_user), do: ""

  defp get_all_emails(%User{emails: emails}) when is_list(emails) do
    Enum.map(emails, & &1.value)
  end

  defp get_all_emails(_user), do: []

  defp get_member_external_ids(%Group{} = _group) do
    # TODO: Implement when group membership provisioning is needed
    # This would require querying for user external_ids for group members
    []
  end
end
