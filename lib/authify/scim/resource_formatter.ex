defmodule Authify.SCIM.ResourceFormatter do
  @moduledoc """
  Formats Authify resources as SCIM 2.0 JSON responses per RFC 7643.

  Converts User and Group models to SCIM-compliant JSON representations
  with proper schemas, meta attributes, and resource links.
  """

  alias Authify.Accounts.{Group, User}

  @user_schema "urn:ietf:params:scim:schemas:core:2.0:User"
  @group_schema "urn:ietf:params:scim:schemas:core:2.0:Group"
  @list_response_schema "urn:ietf:params:scim:api:messages:2.0:ListResponse"
  @error_schema "urn:ietf:params:scim:api:messages:2.0:Error"

  @doc """
  Formats a User as a SCIM User resource.

  ## Parameters
    - user: User struct with preloaded groups
    - base_url: Base URL for constructing resource locations

  ## Returns
    SCIM User resource map
  """
  def format_user(%User{} = user, base_url) do
    %{
      schemas: [@user_schema],
      id: to_string(user.id),
      externalId: user.external_id,
      userName: user.username || user.email,
      name: format_user_name(user),
      emails: format_user_emails(user),
      active: user.active,
      groups: format_user_groups(user, base_url),
      meta: format_meta("User", user, base_url)
    }
    |> remove_nil_values()
  end

  @doc """
  Formats a Group as a SCIM Group resource.

  ## Parameters
    - group: Group struct with preloaded members
    - organization_id: Organization ID for constructing member references
    - base_url: Base URL for constructing resource locations

  ## Returns
    SCIM Group resource map
  """
  def format_group(%Group{} = group, _organization_id, base_url) do
    %{
      schemas: [@group_schema],
      id: to_string(group.id),
      externalId: group.external_id,
      displayName: group.name,
      members: format_group_members(group, base_url),
      meta: format_meta("Group", group, base_url)
    }
    |> remove_nil_values()
  end

  @doc """
  Formats a list of resources as a SCIM ListResponse.

  ## Parameters
    - resources: List of formatted SCIM resources
    - total: Total number of resources matching the query
    - start_index: 1-based index of the first result (SCIM spec)
    - per_page: Number of resources per page

  ## Returns
    SCIM ListResponse map
  """
  def format_list_response(resources, total, start_index, _per_page) do
    %{
      schemas: [@list_response_schema],
      totalResults: total,
      itemsPerPage: length(resources),
      startIndex: start_index,
      Resources: resources
    }
  end

  @doc """
  Formats a SCIM error response.

  ## Parameters
    - status: HTTP status code
    - scim_type: SCIM error type (e.g., "invalidFilter", "uniqueness")
    - detail: Human-readable error message

  ## Returns
    SCIM Error response map

  ## SCIM Error Types
    - invalidFilter: The specified filter syntax is invalid
    - tooMany: Too many results to return
    - uniqueness: One or more attribute values are not unique
    - mutability: Attempted to modify an immutable attribute
    - invalidSyntax: Request body syntax is invalid
    - invalidPath: Path attribute in PATCH is invalid
    - noTarget: Specified path does not exist
    - invalidValue: Attribute value is invalid
    - invalidVers: Specified API version is not supported
    - sensitive: Requested operation contains sensitive data
  """
  def format_error(status, scim_type, detail) do
    %{
      schemas: [@error_schema],
      status: to_string(status),
      scimType: scim_type,
      detail: detail
    }
  end

  # Private functions

  defp format_user_name(%User{first_name: first, last_name: last}) do
    formatted =
      case {first, last} do
        {nil, nil} -> nil
        {f, nil} -> f
        {nil, l} -> l
        {f, l} -> "#{f} #{l}"
      end

    %{
      givenName: first,
      familyName: last,
      formatted: formatted
    }
    |> remove_nil_values()
  end

  defp format_user_emails(%User{email: email}) when is_binary(email) do
    [
      %{
        value: email,
        primary: true,
        type: "work"
      }
    ]
  end

  defp format_user_emails(_user), do: []

  defp format_user_groups(%User{groups: groups}, base_url) when is_list(groups) do
    Enum.map(groups, fn group ->
      %{
        "value" => to_string(group.id),
        "display" => group.name,
        "$ref" => "#{base_url}/Groups/#{group.id}"
      }
    end)
  end

  defp format_user_groups(_user, _base_url), do: []

  defp format_group_members(%Group{users: users}, base_url) when is_list(users) do
    Enum.map(users, fn user ->
      %{
        "value" => to_string(user.id),
        "display" => user.username || user.email,
        "$ref" => "#{base_url}/Users/#{user.id}"
      }
    end)
  end

  defp format_group_members(_group, _base_url), do: []

  defp format_meta(resource_type, resource, base_url) do
    created = resource.scim_created_at || resource.inserted_at
    last_modified = resource.scim_updated_at || resource.updated_at

    %{
      resourceType: resource_type,
      created: format_datetime(created),
      lastModified: format_datetime(last_modified),
      location: "#{base_url}/#{resource_type}s/#{resource.id}"
    }
  end

  defp format_datetime(%DateTime{} = dt) do
    DateTime.to_iso8601(dt)
  end

  defp format_datetime(%NaiveDateTime{} = ndt) do
    ndt
    |> DateTime.from_naive!("Etc/UTC")
    |> DateTime.to_iso8601()
  end

  defp format_datetime(nil), do: nil

  # Recursively remove nil values from maps
  defp remove_nil_values(map) when is_map(map) do
    map
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Enum.into(%{}, fn {k, v} ->
      {k, if(is_map(v), do: remove_nil_values(v), else: v)}
    end)
  end
end
