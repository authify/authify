defmodule AuthifyWeb.SCIM.Helpers do
  @moduledoc """
  Shared helper functions for SCIM controllers.

  Provides common utilities used across all SCIM endpoints including:
  - URL building
  - Error formatting
  - Parameter parsing
  - Pagination
  - Resource validation
  """

  @doc """
  Builds the SCIM base URL for the current organization.

  ## Examples

      iex> build_base_url(conn)
      "https://example.com/my-org/scim/v2"
  """
  def build_base_url(conn) do
    org_slug = conn.assigns[:current_organization].slug
    "#{AuthifyWeb.Endpoint.url()}/#{org_slug}/scim/v2"
  end

  @doc """
  Formats Ecto changeset errors into a human-readable string.

  Handles both simple field errors and nested errors from associations.

  ## Examples

      iex> format_changeset_errors(changeset)
      "email: can't be blank; username: has already been taken"
  """
  def format_changeset_errors(changeset) do
    errors =
      Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
        Enum.reduce(opts, msg, fn {key, value}, acc ->
          String.replace(acc, "%{#{key}}", to_string(value))
        end)
      end)

    Enum.map_join(errors, "; ", fn {field, messages} ->
      formatted_messages = format_error_messages(messages)
      "#{field}: #{formatted_messages}"
    end)
  end

  @doc """
  Safely parses an integer from a string or returns a default value.

  ## Examples

      iex> parse_int("123", 1)
      123

      iex> parse_int("invalid", 1)
      1

      iex> parse_int(nil, 10)
      10

      iex> parse_int(42, 1)
      42
  """
  def parse_int(nil, default), do: default

  def parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end

  def parse_int(value, _default) when is_integer(value), do: value
  def parse_int(_, default), do: default

  @doc """
  Parses SCIM pagination parameters and returns processed values.

  SCIM uses 1-based indexing (startIndex starts at 1), while Authify uses
  0-based page numbers internally.

  ## Parameters
    - params: Map of query parameters
    - max_count: Maximum number of items per page (default: 100)

  ## Returns
    A tuple of {start_index, count, page} where:
    - start_index: The 1-based SCIM startIndex
    - count: Number of items to return per page
    - page: The 0-based page number for internal queries

  ## Examples

      iex> parse_pagination_params(%{"startIndex" => "26", "count" => "25"})
      {26, 25, 2}

      iex> parse_pagination_params(%{})
      {1, 25, 1}

      iex> parse_pagination_params(%{"count" => "200"})
      {1, 100, 1}  # count capped at max_count
  """
  def parse_pagination_params(params, max_count \\ 100) do
    start_index = parse_int(params["startIndex"], 1)
    count = min(parse_int(params["count"], 25), max_count)
    page = div(start_index - 1, count) + 1

    {start_index, count, page}
  end

  @doc """
  Filters a SCIM resource based on attributes and excludedAttributes parameters.

  Per RFC 7644 Section 3.4.2.5, clients can request specific attributes or
  exclude certain attributes from the response.

  ## Parameters
    - resource: The formatted SCIM resource map
    - params: Query parameters map containing "attributes" and/or "excludedAttributes"

  ## Returns
    Filtered SCIM resource map

  ## Notes
    - Always includes: id, schemas, meta (required per RFC)
    - attributes and excludedAttributes are mutually exclusive
    - Supports nested attributes (e.g., "name.givenName")
    - If neither parameter specified, returns full resource

  ## Examples

      iex> filter_attributes(resource, %{"attributes" => "userName,emails"})
      %{"id" => "123", "schemas" => [...], "meta" => {...}, "userName" => "jsmith", "emails" => [...]}

      iex> filter_attributes(resource, %{"excludedAttributes" => "groups"})
      %{"id" => "123", ..., "groups" => nil}  # groups excluded
  """
  def filter_attributes(resource, params) when is_map(params) do
    cond do
      # attributes takes precedence over excludedAttributes
      params["attributes"] && params["attributes"] != "" ->
        apply_attributes_filter(resource, params["attributes"])

      params["excludedAttributes"] && params["excludedAttributes"] != "" ->
        apply_excluded_attributes_filter(resource, params["excludedAttributes"])

      true ->
        resource
    end
  end

  # Private functions for attribute filtering

  # Apply inclusion filter (attributes parameter)
  defp apply_attributes_filter(resource, attributes_param) do
    requested_attrs = parse_attribute_list(attributes_param)

    # Always include these per RFC 7644
    always_included = MapSet.new(["id", "schemas", "meta"])

    # Combine requested with always-included
    included_attrs = MapSet.union(requested_attrs, always_included)

    filter_resource_attributes(resource, included_attrs, :include)
  end

  # Apply exclusion filter (excludedAttributes parameter)
  defp apply_excluded_attributes_filter(resource, excluded_param) do
    excluded_attrs = parse_attribute_list(excluded_param)

    # Never exclude these per RFC 7644
    never_excluded = MapSet.new(["id", "schemas", "meta"])

    # Remove never-excluded from the exclusion list
    excluded_attrs = MapSet.difference(excluded_attrs, never_excluded)

    filter_resource_attributes(resource, excluded_attrs, :exclude)
  end

  # Parse comma-separated attribute list into MapSet
  defp parse_attribute_list(attr_string) when is_binary(attr_string) do
    attr_string
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> MapSet.new()
  end

  defp parse_attribute_list(_), do: MapSet.new()

  # Filter resource based on attribute set
  defp filter_resource_attributes(resource, attr_set, mode) when is_map(resource) do
    resource
    |> Enum.filter(fn {key, _value} ->
      key_string = to_string(key)
      should_include_attribute?(key_string, attr_set, mode)
    end)
    |> Enum.into(%{}, fn {key, value} ->
      # For included attributes, check if we need to filter nested attributes
      filtered_value =
        if mode == :include && is_complex_attribute?(key) do
          filter_nested_attributes(value, key, attr_set)
        else
          value
        end

      {key, filtered_value}
    end)
  end

  # Determine if an attribute should be included based on mode
  defp should_include_attribute?(key, attr_set, :include) do
    # Include if exact match or if it's a parent of a nested attribute
    MapSet.member?(attr_set, key) || has_nested_attributes?(key, attr_set)
  end

  defp should_include_attribute?(key, attr_set, :exclude) do
    # Exclude if exact match
    !MapSet.member?(attr_set, key)
  end

  # Check if there are nested attributes for this parent key
  defp has_nested_attributes?(parent_key, attr_set) do
    prefix = parent_key <> "."

    Enum.any?(attr_set, fn attr ->
      String.starts_with?(attr, prefix)
    end)
  end

  # Filter nested attributes (e.g., name.givenName)
  defp filter_nested_attributes(value, parent_key, attr_set) when is_map(value) do
    parent_key_string = to_string(parent_key)
    # Find all sub-attributes requested for this parent
    sub_attrs =
      attr_set
      |> Enum.filter(fn attr ->
        String.starts_with?(attr, parent_key_string <> ".")
      end)
      |> Enum.map(fn attr ->
        # Extract the sub-attribute name (e.g., "name.givenName" -> "givenName")
        attr
        |> String.replace_prefix(parent_key_string <> ".", "")
        |> String.split(".")
        |> hd()
      end)
      |> MapSet.new()

    if MapSet.size(sub_attrs) > 0 do
      # Filter to only requested sub-attributes
      value
      |> Enum.filter(fn {key, _} ->
        MapSet.member?(sub_attrs, to_string(key))
      end)
      |> Enum.into(%{})
    else
      # Include full value if parent was explicitly requested
      value
    end
  end

  # For lists (e.g., emails), filter each item if it's a map
  defp filter_nested_attributes(value, parent_key, attr_set) when is_list(value) do
    parent_key_string = to_string(parent_key)

    Enum.map(value, fn item ->
      if is_map(item) do
        filter_nested_attributes(item, parent_key_string, attr_set)
      else
        item
      end
    end)
  end

  defp filter_nested_attributes(value, _parent_key, _attr_set), do: value

  # Check if an attribute is complex (has nested structure)
  defp is_complex_attribute?(key) when is_binary(key) do
    key in ["name", "emails", "phoneNumbers", "addresses", "groups", "members"]
  end

  defp is_complex_attribute?(key) when is_atom(key) do
    is_complex_attribute?(Atom.to_string(key))
  end

  @doc """
  Validates that a resource belongs to the given organization.

  Returns :ok if the resource's organization_id matches, otherwise returns
  an error tuple.

  ## Parameters
    - resource: A struct with an organization_id field
    - organization: The organization to validate against

  ## Returns
    - :ok if authorized
    - {:error, :not_found} if unauthorized

  ## Examples

      iex> validate_resource_organization(user, organization)
      :ok

      iex> validate_resource_organization(other_user, organization)
      {:error, :not_found}
  """
  def validate_resource_organization(resource, organization) do
    if resource.organization_id == organization.id do
      :ok
    else
      {:error, :not_found}
    end
  end

  @doc """
  Validates that an attribute value hasn't changed when it's immutable.

  Returns :ok if the field is unchanged or not provided. Returns an error
  tuple with details if an immutable field is being modified.

  ## Parameters
    - attrs: Map of new attributes
    - field: The field name (atom) to check
    - current_value: The current value of the field
    - scim_name: The SCIM attribute name (for error messages)

  ## Returns
    - :ok if validation passes
    - {:error, message} if immutable field is being changed

  ## Examples

      iex> validate_immutable_field(%{external_id: "123"}, :external_id, "123", "externalId")
      :ok

      iex> validate_immutable_field(%{external_id: "456"}, :external_id, "123", "externalId")
      {:error, "Attribute 'externalId' is immutable and cannot be modified"}

      iex> validate_immutable_field(%{}, :external_id, "123", "externalId")
      :ok
  """
  def validate_immutable_field(attrs, field, current_value, scim_name) do
    case Map.get(attrs, field) do
      nil ->
        :ok

      ^current_value ->
        :ok

      _ ->
        {:error, "Attribute '#{scim_name}' is immutable and cannot be modified"}
    end
  end

  # Private functions

  defp format_error_messages(messages) when is_list(messages) do
    messages
    |> Enum.map_join(", ", &format_error_message/1)
  end

  defp format_error_messages(message), do: to_string(message)

  defp format_error_message(message) when is_binary(message), do: message
  defp format_error_message(message) when is_map(message), do: inspect(message)
  defp format_error_message(message), do: to_string(message)
end
