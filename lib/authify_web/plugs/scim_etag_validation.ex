defmodule AuthifyWeb.Plugs.SCIMETagValidation do
  @moduledoc """
  Validates SCIM ETag headers for conditional requests per RFC 7644 Section 3.14.

  Handles:
  - `If-Match` on PUT/PATCH/DELETE (optimistic concurrency control)
  - `If-None-Match` on GET (client-side caching)

  Returns:
  - 412 Precondition Failed if If-Match doesn't match current version
  - 304 Not Modified if If-None-Match matches current version
  """

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  alias Authify.Accounts
  alias Authify.SCIM.ResourceFormatter
  alias Authify.SCIM.Version

  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    cond do
      # If-Match header on mutating operations (PUT/PATCH/DELETE)
      conn.method in ["PUT", "PATCH", "DELETE"] && get_req_header(conn, "if-match") != [] ->
        validate_if_match(conn)

      # If-None-Match header on GET operations
      conn.method == "GET" && get_req_header(conn, "if-none-match") != [] ->
        validate_if_none_match(conn)

      # No conditional headers, continue normally
      true ->
        conn
    end
  end

  # Private functions

  defp validate_if_match(conn) do
    with [if_match] <- get_req_header(conn, "if-match"),
         {:ok, resource} <- fetch_resource(conn),
         provided_version <- Version.parse_etag(if_match),
         current_version <- Version.generate_version(resource),
         true <- provided_version == current_version do
      # Version matches, continue with the request
      conn
    else
      # Version mismatch or resource not found
      _ ->
        send_precondition_failed(conn)
    end
  end

  defp validate_if_none_match(conn) do
    with [if_none_match] <- get_req_header(conn, "if-none-match"),
         {:ok, resource} <- fetch_resource(conn),
         provided_version <- Version.parse_etag(if_none_match),
         current_version <- Version.generate_version(resource),
         true <- provided_version == current_version do
      # Version matches, resource hasn't changed
      send_not_modified(conn)
    else
      # Version mismatch or resource not found, continue normally
      _ ->
        conn
    end
  end

  defp fetch_resource(conn) do
    case conn.path_info do
      # /Me endpoint - use authenticated user
      [_org_slug, "scim", "v2", "Me" | _] ->
        fetch_me(conn)

      # Path with organization slug: /org-slug/scim/v2/Users/123
      [_org_slug, "scim", "v2", "Users", user_id | _] ->
        fetch_user(conn, user_id)

      [_org_slug, "scim", "v2", "Groups", group_id | _] ->
        fetch_group(conn, group_id)

      # Path without organization slug (legacy/fallback)
      ["scim", "v2", "Me" | _] ->
        fetch_me(conn)

      ["scim", "v2", "Users", user_id | _] ->
        fetch_user(conn, user_id)

      ["scim", "v2", "Groups", group_id | _] ->
        fetch_group(conn, group_id)

      _ ->
        {:error, :not_found}
    end
  end

  defp fetch_me(conn) do
    case conn.assigns[:current_user] do
      nil ->
        {:error, :not_found}

      user ->
        # Refetch from DB to get latest scim_updated_at timestamp
        org = conn.assigns[:current_organization]

        case Accounts.get_user_in_organization(user.id, org.id) do
          nil -> {:error, :not_found}
          fresh_user -> {:ok, fresh_user}
        end
    end
  end

  defp fetch_user(conn, user_id) do
    org = conn.assigns[:current_organization]

    case Accounts.get_user_in_organization(user_id, org.id) do
      nil -> {:error, :not_found}
      user -> {:ok, user}
    end
  end

  defp fetch_group(conn, group_id) do
    org = conn.assigns[:current_organization]

    case Accounts.get_group(group_id) do
      nil ->
        {:error, :not_found}

      group ->
        if group.organization_id == org.id do
          {:ok, group}
        else
          {:error, :not_found}
        end
    end
  end

  defp send_precondition_failed(conn) do
    error =
      ResourceFormatter.format_error(
        412,
        "invalidVers",
        "Resource version mismatch. The resource has been modified by another request."
      )

    conn
    |> put_resp_content_type("application/scim+json")
    |> put_status(412)
    |> json(error)
    |> halt()
  end

  defp send_not_modified(conn) do
    conn
    |> put_status(304)
    |> send_resp(304, "")
    |> halt()
  end
end
