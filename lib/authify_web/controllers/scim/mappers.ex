defmodule AuthifyWeb.SCIM.Mappers do
  @moduledoc """
  Shared SCIM attribute mapping functions.

  Handles mapping between SCIM 2.0 resource representations and Authify's
  internal data structures for both Users and Groups.
  """

  @doc """
  Maps SCIM user attributes to Authify user attributes.

  Handles:
  - userName (can be username or email)
  - externalId
  - name.givenName and name.familyName
  - emails array
  - active status

  Returns a map suitable for passing to Accounts.create_user_scim/2 or
  Accounts.update_user_scim/2.
  """
  def map_user_attrs(params) do
    %{}
    |> map_username_field(params)
    |> map_external_id(params)
    |> map_name_fields(params)
    |> map_email_fields(params)
    |> map_active_field(params)
  end

  @doc """
  Maps SCIM group attributes to Authify group attributes.

  Handles:
  - displayName
  - externalId

  Returns a map suitable for passing to Accounts.create_group_scim/2 or
  Accounts.update_group_scim/2.
  """
  def map_group_attrs(params) do
    %{}
    |> map_display_name(params)
    |> map_group_external_id(params)
  end

  # Private functions for user mapping

  defp map_username_field(attrs, params) do
    case params["userName"] do
      nil ->
        {attrs, nil}

      username when is_binary(username) ->
        if String.contains?(username, "@") do
          # userName is an email address
          {attrs, username}
        else
          # userName is a username
          {Map.put(attrs, :username, username), nil}
        end
    end
  end

  defp map_external_id({attrs, username_email}, params) do
    attrs =
      if params["externalId"],
        do: Map.put(attrs, :external_id, params["externalId"]),
        else: attrs

    {attrs, username_email}
  end

  defp map_name_fields({attrs, username_email}, params) do
    attrs =
      attrs
      |> maybe_put(:first_name, get_in(params, ["name", "givenName"]))
      |> maybe_put(:last_name, get_in(params, ["name", "familyName"]))

    {attrs, username_email}
  end

  defp map_email_fields({attrs, username_email}, params) do
    emails = build_email_list(params, username_email)
    Map.put(attrs, :emails, emails)
  end

  defp map_active_field(attrs, params) do
    if Map.has_key?(params, "active"),
      do: Map.put(attrs, :active, params["active"]),
      else: attrs
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

  # Private functions for group mapping

  defp map_display_name(attrs, params) do
    if params["displayName"],
      do: Map.put(attrs, :name, params["displayName"]),
      else: attrs
  end

  defp map_group_external_id(attrs, params) do
    if params["externalId"],
      do: Map.put(attrs, :external_id, params["externalId"]),
      else: attrs
  end

  # Shared helper

  defp maybe_put(attrs, _key, nil), do: attrs
  defp maybe_put(attrs, key, value), do: Map.put(attrs, key, value)
end
