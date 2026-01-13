defmodule Authify.SCIM.FilterParser do
  @moduledoc """
  SCIM 2.0 filter expression parser per RFC 7644 Section 3.4.2.2.

  Parses SCIM filter strings into an Abstract Syntax Tree (AST) that can
  be converted to database queries.

  ## Examples

      iex> Authify.SCIM.FilterParser.parse("userName eq \\"jsmith\\"")
      {:ok, {:eq, "userName", "jsmith"}}

      iex> Authify.SCIM.FilterParser.parse("active eq true and userName sw \\"j\\"")
      {:ok, {:and, {:eq, "active", "true"}, {:sw, "userName", "j"}}}

  ## Adapted from ExScim

  This implementation is adapted from the ExScim library:
  - Copyright (c) 2025 wheredoipressnow
  - Licensed under the MIT License
  - Original source: https://github.com/ExScim/ex_scim

  Special thanks to the ExScim project for their excellent SCIM filter parser
  implementation using NimbleParsec.
  """

  import NimbleParsec
  import Authify.SCIM.Lexical

  # --------------------------
  # Helper reducer functions
  # --------------------------

  # Map of SCIM operators to atoms (avoids String.to_atom/1 and reduces complexity)
  @operator_map %{
    "eq" => :eq,
    "ne" => :ne,
    "co" => :co,
    "sw" => :sw,
    "ew" => :ew,
    "gt" => :gt,
    "ge" => :ge,
    "lt" => :lt,
    "le" => :le,
    "pr" => :pr,
    "and" => :and,
    "or" => :or,
    "not" => :not
  }

  @doc false
  def to_op(op), do: Map.fetch!(@operator_map, String.downcase(op))

  @doc false
  def to_comp_ast([attr, op, val]), do: {to_op(op), attr, val}

  @doc false
  def to_present_ast(attr), do: {:pr, attr}

  @doc false
  def to_not_ast(expr), do: {:not, expr}

  @doc false
  def to_comp_ast_wrapped([{_, attr}, {_, op}, {_, val}]) do
    {to_op(op), attr, val}
  end

  @doc false
  def reduce_logical_chain([head | rest]) do
    Enum.chunk_every(rest, 2)
    |> Enum.reduce(head, fn [op, right], acc -> {op, acc, right} end)
  end

  @doc false
  def join_path([first | rest]), do: Enum.join([first | rest], ".")

  @doc false
  def to_attribute_filter_ast([target | filter]), do: {target, filter}

  # --------------------------
  # Combinators
  # --------------------------

  defcombinatorp(
    :compare_op,
    choice(
      Enum.map(
        ~w(eq ne co sw ew gt lt ge le Eq Ne Co Sw Ew Gt Lt Ge Le eQ nE cO sW eW gT lT gE lE EQ NE CO SW EW GT LT GE LE),
        &string/1
      )
    )
  )

  defcombinatorp(
    :attr_char,
    ascii_char([?a..?z, ?A..?Z, ?0..?9, ?_, ?-, ?:, ?/])
  )

  defcombinatorp(
    :attr_name,
    ascii_string([?a..?z, ?A..?Z, ?0..?9, ?_, ?-, ?:, ?/], min: 1)
  )

  defcombinatorp(
    :attr_path,
    parsec(:attr_name)
    |> repeat(
      ignore(string("."))
      |> concat(parsec(:attr_name))
    )
    |> reduce({__MODULE__, :join_path, []})
  )

  defcombinatorp(
    :filtered_attr_expr,
    parsec(:attr_path)
    |> ignore(string("["))
    |> concat(parsec(:val_filter))
    |> ignore(string("]"))
    |> reduce({__MODULE__, :to_attribute_filter_ast, []})
  )

  defcombinatorp(
    :attr_exp,
    parsec(:attr_path)
    |> optional(
      ignore(string("["))
      |> concat(parsec(:val_filter))
      |> ignore(string("]"))
    )
  )

  defcombinatorp(
    :logical_op,
    ignore(wsp())
    |> choice([
      string("and"),
      string("And"),
      string("aNd"),
      string("anD"),
      string("ANd"),
      string("aND"),
      string("AnD"),
      string("AND"),
      string("or"),
      string("Or"),
      string("oR"),
      string("OR")
    ])
    |> map({__MODULE__, :to_op, []})
    |> ignore(wsp())
  )

  defcombinatorp(
    :comp_exp,
    parsec(:attr_exp)
    |> map({List, :wrap, []})
    |> ignore(wsp())
    |> concat(parsec(:compare_op) |> map({List, :wrap, []}))
    |> ignore(wsp())
    |> concat(comp_value() |> map({List, :wrap, []}))
    |> reduce({Enum, :concat, []})
    |> map({__MODULE__, :to_comp_ast, []})
  )

  defcombinatorp(
    :present_exp,
    parsec(:attr_exp)
    |> ignore(wsp())
    |> ignore(choice([string("pr"), string("Pr"), string("pR"), string("PR")]))
    |> map({__MODULE__, :to_present_ast, []})
  )

  defcombinatorp(
    :not_exp,
    ignore(
      choice([
        string("not"),
        string("Not"),
        string("nOt"),
        string("noT"),
        string("NOt"),
        string("nOT"),
        string("NoT"),
        string("NOT")
      ])
    )
    |> ignore(wsp())
    |> ignore(string("("))
    |> concat(parsec(:val_filter))
    |> ignore(string(")"))
    |> map({__MODULE__, :to_not_ast, []})
  )

  defcombinatorp(
    :paren_exp,
    ignore(string("("))
    |> concat(parsec(:val_filter))
    |> ignore(string(")"))
  )

  # primary_expr ::= basic atomic expressions
  defcombinatorp(
    :primary_expr,
    choice([
      parsec(:filtered_attr_expr),
      parsec(:comp_exp),
      parsec(:present_exp),
      parsec(:not_exp),
      parsec(:paren_exp)
    ])
  )

  # and_expr ::= primary_expr ("and" primary_expr)*
  defcombinatorp(
    :and_expr,
    parsec(:primary_expr)
    |> repeat(parsec(:logical_op) |> concat(parsec(:primary_expr)))
    |> reduce({__MODULE__, :reduce_logical_chain, []})
  )

  # or_expr ::= and_expr ("or" and_expr)*
  defcombinatorp(
    :or_expr,
    parsec(:and_expr)
    |> repeat(parsec(:logical_op) |> concat(parsec(:and_expr)))
    |> reduce({__MODULE__, :reduce_logical_chain, []})
  )

  defcombinatorp(:val_filter, parsec(:or_expr))

  # Main parser entry point
  defparsec(:do_parse, parsec(:val_filter) |> eos())

  @doc """
  Parses a SCIM filter expression string into an AST.

  Returns `{:ok, ast}` on success or `{:error, reason}` on parse failure.

  ## Examples

      iex> parse("userName eq \\"jsmith\\"")
      {:ok, {:eq, "userName", "jsmith"}}

      iex> parse("active eq true")
      {:ok, {:eq, "active", "true"}}

      iex> parse("invalid filter!")
      {:error, "Parse error at position 8..."}
  """
  def parse(filter_string) when is_binary(filter_string) do
    case do_parse(filter_string) do
      {:ok, [ast], "", _, _, _} ->
        {:ok, ast}

      {:ok, _, rest, _, _, _} ->
        {:error, "Unexpected characters after filter: #{rest}"}

      {:error, reason, _rest, _, _, _} ->
        {:error, "Parse error: #{reason}"}
    end
  end

  def parse(nil), do: {:ok, nil}
  def parse(_), do: {:error, "Filter must be a string"}
end
