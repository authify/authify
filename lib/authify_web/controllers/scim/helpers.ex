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
