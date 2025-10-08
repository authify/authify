defmodule AuthifyWeb.API.BaseController do
  @moduledoc """
  Base controller for Management API endpoints.

  Provides common functionality for HATEOAS responses, pagination,
  error handling, and consistent JSON API formatting.
  """

  import Plug.Conn
  import Phoenix.Controller

  defmacro __using__(_opts) do
    quote do
      use AuthifyWeb, :controller
      import AuthifyWeb.API.BaseController
    end
  end

  @doc """
  Render a successful API response with HATEOAS links.
  """
  def render_api_response(conn, data, opts \\ []) do
    opts_with_conn = Keyword.put(opts, :conn, conn)

    response = %{
      data: format_resource(data, opts_with_conn),
      links: generate_links(conn, data, opts)
    }

    response =
      if opts[:meta] do
        Map.put(response, :meta, opts[:meta])
      else
        response
      end

    conn
    |> put_status(opts[:status] || :ok)
    |> json(response)
  end

  @doc """
  Render a paginated collection response.
  """
  def render_collection_response(conn, collection, opts \\ []) do
    page_info = opts[:page_info] || %{}
    opts_with_conn = Keyword.put(opts, :conn, conn)

    response = %{
      data: Enum.map(collection, &format_resource(&1, opts_with_conn)),
      links: generate_collection_links(conn, page_info),
      meta: %{
        total: page_info[:total] || length(collection),
        page: page_info[:page] || 1,
        per_page: page_info[:per_page] || length(collection)
      }
    }

    conn
    |> put_status(:ok)
    |> json(response)
  end

  @doc """
  Render an API error response.
  """
  def render_error_response(conn, status, error_type, message, details \\ nil) do
    error = %{
      type: error_type,
      message: message
    }

    error =
      if details do
        Map.put(error, :details, details)
      else
        error
      end

    response = %{
      error: error,
      links: %{
        documentation: "/developers/errors"
      }
    }

    conn
    |> put_status(status)
    |> json(response)
  end

  @doc """
  Handle validation errors from changesets.
  """
  def render_validation_errors(conn, changeset) do
    errors =
      Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
        Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
          opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
        end)
      end)

    render_error_response(
      conn,
      :unprocessable_entity,
      "validation_failed",
      "The request data failed validation",
      errors
    )
  end

  # Private helper functions

  defp format_resource(resource, opts) when is_map(resource) do
    resource_type = opts[:resource_type] || infer_resource_type(resource)

    %{
      id: to_string(resource.id),
      type: resource_type,
      attributes: extract_attributes(resource, opts),
      links: generate_resource_links(resource, resource_type, opts)
    }
  end

  defp format_resource(resource, _opts), do: resource

  defp extract_attributes(resource, opts) do
    excluded_fields = [:id, :__meta__, :__struct__] ++ (opts[:exclude] || [])

    # Encode to JSON to respect @derive configuration, then decode back
    json_map =
      resource
      |> Jason.encode!()
      |> Jason.decode!()

    # Handle special client_secret_display field for OAuth applications
    json_map =
      if Map.has_key?(resource, :client_secret_display) do
        Map.put(json_map, "client_secret", resource.client_secret_display)
      else
        json_map
      end

    # Remove excluded fields (client_secret unless we're showing it)
    excluded_field_strings = Enum.map(excluded_fields, &to_string/1)

    json_map
    |> Map.drop(excluded_field_strings)
  end

  defp infer_resource_type(resource) do
    resource.__struct__
    |> Module.split()
    |> List.last()
    |> Macro.underscore()
  end

  defp generate_resource_links(resource, resource_type, opts) do
    conn = opts[:conn]
    org_slug = get_org_slug(conn)
    base_path = "/#{org_slug}/api/#{pluralize_resource_type(resource_type)}"

    %{
      self: "#{base_path}/#{resource.id}"
    }
  end

  defp pluralize_resource_type("organization"), do: "organization"
  defp pluralize_resource_type("user"), do: "users"
  defp pluralize_resource_type("application"), do: "applications"
  # defp pluralize_resource_type("saml_provider"), do: "saml-providers"
  defp pluralize_resource_type("service_provider"), do: "saml-providers"
  defp pluralize_resource_type("certificate"), do: "certificates"
  defp pluralize_resource_type("invitation"), do: "invitations"
  defp pluralize_resource_type(type), do: "#{type}s"

  @doc """
  Ensures the current request has the required scope.
  Returns :ok if authorized, or {:error, response} if not.
  """
  def ensure_scope(conn, required_scope) do
    scopes = conn.assigns[:current_scopes] || []

    if has_required_scope?(scopes, required_scope) do
      :ok
    else
      response =
        conn
        |> put_status(:forbidden)
        |> json(%{
          error: %{
            type: "insufficient_scope",
            message: "Insufficient scope to access this resource",
            details: %{
              required: required_scope,
              provided: scopes
            }
          },
          links: %{
            documentation: "/developers/scopes"
          }
        })
        |> halt()

      {:error, response}
    end
  end

  defp has_required_scope?(user_scopes, required_scope) do
    Enum.any?(user_scopes, fn user_scope ->
      scope_matches?(user_scope, required_scope)
    end)
  end

  defp scope_matches?(user_scope, required_scope) do
    # Exact match or write scope includes corresponding read scope
    # e.g., "certificates:write" includes "certificates:read"
    user_scope == required_scope or
      (String.ends_with?(user_scope, ":write") and
         String.replace_suffix(user_scope, ":write", ":read") == required_scope)
  end

  defp generate_links(conn, _data, _opts) do
    %{
      self: current_url(conn)
    }
  end

  defp generate_collection_links(conn, page_info) do
    base_url = current_url_without_query(conn)
    current_page = page_info[:page] || 1
    per_page = page_info[:per_page] || 25
    total = page_info[:total] || 0

    links = %{
      self: current_url(conn),
      first: "#{base_url}?page=1&per_page=#{per_page}"
    }

    # Add prev link if not on first page
    links =
      if current_page > 1 do
        Map.put(links, :prev, "#{base_url}?page=#{current_page - 1}&per_page=#{per_page}")
      else
        links
      end

    # Add next link if there are more pages
    total_pages = ceil(total / per_page)

    links =
      if current_page < total_pages do
        Map.put(links, :next, "#{base_url}?page=#{current_page + 1}&per_page=#{per_page}")
      else
        links
      end

    # Add last link
    if total_pages > 1 do
      Map.put(links, :last, "#{base_url}?page=#{total_pages}&per_page=#{per_page}")
    else
      links
    end
  end

  defp current_url_without_query(conn) do
    conn.request_path
  end

  defp get_org_slug(conn) do
    conn.path_params["org_slug"] || conn.assigns.current_organization.slug
  end
end
