defmodule Authify.FilterSort do
  @moduledoc """
  Utilities for filtering and sorting query results.

  This module provides common functionality for parsing filter and sort parameters
  from HTTP requests and applying them to Ecto queries.
  """

  import Ecto.Query

  @doc """
  Applies sorting to a query based on sort and order parameters.

  ## Parameters
    * `query` - The Ecto query to sort
    * `sort_field` - The field to sort by (string or atom)
    * `order` - Sort order ("asc" or "desc", defaults to "asc")
    * `allowed_fields` - List of allowed sort fields (atoms)

  ## Examples

      iex> apply_sort(User, "name", "asc", [:name, :email])
      #Ecto.Query<...>
  """
  def apply_sort(query, sort_field, order \\ "asc", allowed_fields) do
    field_atom = normalize_field(sort_field)
    order_atom = normalize_order(order)

    if field_atom in allowed_fields do
      order_by(query, ^[{order_atom, field_atom}])
    else
      query
    end
  end

  @doc """
  Applies text search filtering to a query for a given field.

  ## Parameters
    * `query` - The Ecto query to filter
    * `field` - The field to search in
    * `search_term` - The text to search for (uses LIKE)

  ## Examples

      iex> apply_text_filter(User, :email, "test@")
      #Ecto.Query<...>
  """
  def apply_text_filter(query, _field, nil), do: query
  def apply_text_filter(query, _field, ""), do: query

  def apply_text_filter(query, field, search_term) when is_binary(search_term) do
    search_pattern = "%#{search_term}%"
    where(query, [q], like(field(q, ^field), ^search_pattern))
  end

  @doc """
  Applies exact match filtering to a query for a given field.

  ## Parameters
    * `query` - The Ecto query to filter
    * `field` - The field to filter on
    * `value` - The value to match exactly

  ## Examples

      iex> apply_exact_filter(User, :role, "admin")
      #Ecto.Query<...>
  """
  def apply_exact_filter(query, _field, nil), do: query
  def apply_exact_filter(query, _field, ""), do: query

  def apply_exact_filter(query, field, value) do
    where(query, [q], field(q, ^field) == ^value)
  end

  @doc """
  Applies boolean filtering to a query for a given field.

  ## Parameters
    * `query` - The Ecto query to filter
    * `field` - The field to filter on (must be boolean)
    * `value` - String "true" or "false"

  ## Examples

      iex> apply_boolean_filter(User, :active, "true")
      #Ecto.Query<...>
  """
  def apply_boolean_filter(query, _field, nil), do: query
  def apply_boolean_filter(query, _field, ""), do: query

  def apply_boolean_filter(query, field, "true"), do: where(query, [q], field(q, ^field) == true)

  def apply_boolean_filter(query, field, "false"),
    do: where(query, [q], field(q, ^field) == false)

  def apply_boolean_filter(query, _field, _value), do: query

  @doc """
  Parses filter parameters from Phoenix params.

  Expects filters in the format: `filter[field_name]=value`

  ## Examples

      iex> parse_filters(%{"filter" => %{"status" => "active", "role" => "admin"}})
      %{status: "active", role: "admin"}
  """
  def parse_filters(params) do
    case Map.get(params, "filter") do
      nil ->
        %{}

      filters when is_map(filters) ->
        Enum.into(filters, %{}, fn {k, v} -> {String.to_existing_atom(k), v} end)
    end
  rescue
    ArgumentError -> %{}
  end

  # Private helpers

  defp normalize_field(field) when is_binary(field) do
    String.to_existing_atom(field)
  rescue
    ArgumentError -> nil
  end

  defp normalize_field(field) when is_atom(field), do: field
  defp normalize_field(_), do: nil

  defp normalize_order("desc"), do: :desc
  defp normalize_order("DESC"), do: :desc
  defp normalize_order(_), do: :asc
end
