defmodule Authify.SCIM.QueryFilter do
  @moduledoc """
  Converts SCIM filter ASTs to Ecto dynamic queries.

  Takes a parsed SCIM filter expression (from `Authify.SCIM.FilterParser`)
  and converts it into an Ecto dynamic query that can be applied to User
  or Group queries.

  ## Security

  Unlike the original ExScim implementation, this module uses an allowlist
  approach via `Authify.SCIM.AttributeMapper` to prevent atom table exhaustion
  attacks from untrusted SCIM filter expressions.

  ## Adapted from ExScim

  This implementation is adapted from the ExScimEcto library:
  - Copyright (c) 2025 wheredoipressnow
  - Licensed under the MIT License
  - Original source: https://github.com/ExScim/ex_scim_ecto

  Modified to use allowlisted attribute mapping instead of `String.to_atom/1`
  for improved security.

  ## Examples

      iex> ast = {:eq, "userName", "jsmith"}
      iex> QueryFilter.apply_filter(User, ast, :user)
      #Ecto.Query<...>

      iex> ast = {:and, {:eq, "active", "true"}, {:sw, "userName", "j"}}
      iex> QueryFilter.apply_filter(User, ast, :user)
      #Ecto.Query<...>
  """

  import Ecto.Query
  alias Authify.SCIM.AttributeMapper

  @doc """
  Applies a SCIM filter AST to an Ecto query.

  Returns the modified query with the filter applied as a WHERE clause,
  or `{:error, reason}` if the filter contains invalid attributes.

  ## Parameters
    * `query` - Base Ecto query (e.g., `User` or `from(u in User)`)
    * `ast` - Parsed filter AST from `FilterParser.parse/1`
    * `resource_type` - Either `:user` or `:group`

  ## Examples

      iex> from(u in User) |> QueryFilter.apply_filter({:eq, "userName", "jsmith"}, :user)
      #Ecto.Query<from u in User, where: u.username == ^"jsmith">
  """
  def apply_filter(query, nil, _resource_type), do: {:ok, query}

  def apply_filter(query, ast, resource_type) do
    case build_dynamic(ast, resource_type) do
      {:ok, dynamic} ->
        {:ok, from(q in query, where: ^dynamic)}

      {:error, _} = error ->
        error
    end
  end

  # Build dynamic query from AST
  defp build_dynamic({:eq, field, value}, resource_type) do
    with {:ok, field_atom} <- AttributeMapper.scim_to_ecto_field(field, resource_type) do
      {:ok, dynamic([r], field(r, ^field_atom) == ^normalize_value(value))}
    end
  end

  defp build_dynamic({:ne, field, value}, resource_type) do
    with {:ok, field_atom} <- AttributeMapper.scim_to_ecto_field(field, resource_type) do
      {:ok, dynamic([r], field(r, ^field_atom) != ^normalize_value(value))}
    end
  end

  defp build_dynamic({:co, field, value}, resource_type) do
    with {:ok, field_atom} <- AttributeMapper.scim_to_ecto_field(field, resource_type) do
      # "contains" operator - case-insensitive (MySQL like is case-insensitive by default)
      {:ok, dynamic([r], like(field(r, ^field_atom), ^"%#{value}%"))}
    end
  end

  defp build_dynamic({:sw, field, value}, resource_type) do
    with {:ok, field_atom} <- AttributeMapper.scim_to_ecto_field(field, resource_type) do
      # "starts with" operator - case-insensitive (MySQL like is case-insensitive by default)
      {:ok, dynamic([r], like(field(r, ^field_atom), ^"#{value}%"))}
    end
  end

  defp build_dynamic({:ew, field, value}, resource_type) do
    with {:ok, field_atom} <- AttributeMapper.scim_to_ecto_field(field, resource_type) do
      # "ends with" operator - case-insensitive (MySQL like is case-insensitive by default)
      {:ok, dynamic([r], like(field(r, ^field_atom), ^"%#{value}"))}
    end
  end

  defp build_dynamic({:pr, field}, resource_type) do
    with {:ok, field_atom} <- AttributeMapper.scim_to_ecto_field(field, resource_type) do
      # "present" operator - field is not null
      {:ok, dynamic([r], not is_nil(field(r, ^field_atom)))}
    end
  end

  defp build_dynamic({:gt, field, value}, resource_type) do
    with {:ok, field_atom} <- AttributeMapper.scim_to_ecto_field(field, resource_type) do
      {:ok, dynamic([r], field(r, ^field_atom) > ^normalize_value(value))}
    end
  end

  defp build_dynamic({:ge, field, value}, resource_type) do
    with {:ok, field_atom} <- AttributeMapper.scim_to_ecto_field(field, resource_type) do
      {:ok, dynamic([r], field(r, ^field_atom) >= ^normalize_value(value))}
    end
  end

  defp build_dynamic({:lt, field, value}, resource_type) do
    with {:ok, field_atom} <- AttributeMapper.scim_to_ecto_field(field, resource_type) do
      {:ok, dynamic([r], field(r, ^field_atom) < ^normalize_value(value))}
    end
  end

  defp build_dynamic({:le, field, value}, resource_type) do
    with {:ok, field_atom} <- AttributeMapper.scim_to_ecto_field(field, resource_type) do
      {:ok, dynamic([r], field(r, ^field_atom) <= ^normalize_value(value))}
    end
  end

  defp build_dynamic({:and, left, right}, resource_type) do
    with {:ok, left_dynamic} <- build_dynamic(left, resource_type),
         {:ok, right_dynamic} <- build_dynamic(right, resource_type) do
      {:ok, dynamic([r], ^left_dynamic and ^right_dynamic)}
    end
  end

  defp build_dynamic({:or, left, right}, resource_type) do
    with {:ok, left_dynamic} <- build_dynamic(left, resource_type),
         {:ok, right_dynamic} <- build_dynamic(right, resource_type) do
      {:ok, dynamic([r], ^left_dynamic or ^right_dynamic)}
    end
  end

  defp build_dynamic({:not, expr}, resource_type) do
    with {:ok, expr_dynamic} <- build_dynamic(expr, resource_type) do
      {:ok, dynamic([r], not (^expr_dynamic))}
    end
  end

  # Handle complex attribute paths (e.g., emails[type eq "work"].value)
  # For now, we simplify by just using the target field
  # Full implementation would need to handle the filter on the array element
  defp build_dynamic({target, _filter}, resource_type) when is_binary(target) do
    # This is a filtered attribute expression like emails[type eq "work"].value
    # For simplicity, we just check if the target field is present
    # A full implementation would need to handle JSON queries or associations
    with {:ok, field_atom} <- AttributeMapper.scim_to_ecto_field(target, resource_type) do
      {:ok, dynamic([r], not is_nil(field(r, ^field_atom)))}
    end
  end

  # Normalize SCIM string values to appropriate Elixir types
  defp normalize_value("true"), do: true
  defp normalize_value("false"), do: false
  defp normalize_value("null"), do: nil
  defp normalize_value(value) when is_binary(value), do: value
  defp normalize_value(value), do: value
end
