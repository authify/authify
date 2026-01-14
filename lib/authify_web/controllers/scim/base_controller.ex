defmodule AuthifyWeb.SCIM.BaseController do
  @moduledoc """
  Base controller for SCIM 2.0 endpoints.

  Provides common functionality for rendering SCIM responses with proper
  content types and error handling per RFC 7644.
  """

  import Plug.Conn
  import Phoenix.Controller

  alias Authify.SCIM.ResourceFormatter

  @scim_content_type "application/scim+json"

  @doc """
  Renders a single SCIM resource.

  ## Parameters
    - conn: Plug connection
    - resource: Formatted SCIM resource map
    - opts: Optional keyword list
      - :status - HTTP status code (default: 200)

  ## Examples
      render_scim_resource(conn, user_resource)
      render_scim_resource(conn, user_resource, status: 201)
  """
  def render_scim_resource(conn, resource, opts \\ []) do
    status = Keyword.get(opts, :status, 200)

    conn
    |> put_resp_content_type(@scim_content_type)
    |> put_status(status)
    |> json(resource)
  end

  @doc """
  Renders a SCIM ListResponse.

  ## Parameters
    - conn: Plug connection
    - resources: List of formatted SCIM resources
    - total: Total number of resources matching the query
    - start_index: 1-based index of first result (SCIM spec)
    - per_page: Number of resources per page
    - resource_type: :user or :group (for HATEOAS links)

  ## Examples
      render_scim_list(conn, users, 100, 1, 25, :user)
  """
  def render_scim_list(conn, resources, total, start_index, per_page, _resource_type) do
    response = ResourceFormatter.format_list_response(resources, total, start_index, per_page)

    conn
    |> put_resp_content_type(@scim_content_type)
    |> put_status(200)
    |> json(response)
  end

  @doc """
  Renders a SCIM error response.

  ## Parameters
    - conn: Plug connection
    - status: HTTP status code
    - scim_type: SCIM error type atom or string
    - detail: Human-readable error message

  ## SCIM Error Types
    - :invalid_filter - The specified filter syntax is invalid
    - :too_many - Too many results to return
    - :uniqueness - One or more attribute values are not unique
    - :mutability - Attempted to modify an immutable attribute
    - :invalid_syntax - Request body syntax is invalid
    - :invalid_path - Path attribute in PATCH is invalid
    - :no_target - Specified path does not exist
    - :invalid_value - Attribute value is invalid
    - :invalid_vers - Specified API version is not supported
    - :sensitive - Requested operation contains sensitive data

  ## Examples
      render_scim_error(conn, 400, :invalid_filter, "Invalid filter syntax")
      render_scim_error(conn, 404, :no_target, "User not found")
      render_scim_error(conn, 409, :uniqueness, "User already exists")
  """
  def render_scim_error(conn, status, scim_type, detail) do
    scim_type_string = normalize_scim_type(scim_type)

    error = ResourceFormatter.format_error(status, scim_type_string, detail)

    conn
    |> put_resp_content_type(@scim_content_type)
    |> put_status(status)
    |> json(error)
  end

  @doc """
  Ensures the request has the required SCIM OAuth scope.

  Uses the same scope checking pattern as APIAuth for consistency.

  ## Parameters
    - conn: Plug connection
    - required_scope: Scope string (e.g., "scim:read", "scim:users:write")

  ## Returns
    - {:ok, conn} if authorized
    - {:error, :unauthorized} if not authorized

  ## Examples
      case ensure_scim_scope(conn, "scim:users:read") do
        {:ok, conn} -> # continue
        {:error, :unauthorized} -> render_scim_error(conn, 403, :sensitive, "Insufficient scope")
      end
  """
  def ensure_scim_scope(conn, required_scope) do
    scopes = conn.assigns[:current_scopes] || []

    if has_scope?(scopes, required_scope) do
      {:ok, conn}
    else
      {:error, :unauthorized}
    end
  end

  # Private functions

  defp normalize_scim_type(type) when is_atom(type) do
    type
    |> Atom.to_string()
    |> Macro.camelize()
    |> then(&(String.downcase(String.first(&1)) <> String.slice(&1, 1..-1//1)))
  end

  defp normalize_scim_type(type) when is_binary(type), do: type

  # Scope checking - mirrors APIAuth.scope_matches?/2
  defp has_scope?(scopes, required_scope) do
    Enum.any?(scopes, fn scope ->
      scope_matches?(scope, required_scope)
    end)
  end

  defp scope_matches?(user_scope, required_scope) do
    # Exact match or write includes read
    user_scope == required_scope or
      (String.ends_with?(user_scope, ":write") and
         String.replace_suffix(user_scope, ":write", ":read") == required_scope)
  end

  @doc false
  defmacro __using__(_opts) do
    quote do
      use AuthifyWeb, :controller
      import AuthifyWeb.SCIM.BaseController
    end
  end
end
