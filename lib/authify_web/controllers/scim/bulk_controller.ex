defmodule AuthifyWeb.SCIM.BulkController do
  @moduledoc """
  SCIM 2.0 Bulk operations endpoint per RFC 7644 Section 3.7.

  Enables clients to send multiple resource operations in a single request.
  Supports bulkId references for dependent operations and configurable error handling.
  """

  use AuthifyWeb.SCIM.BaseController

  alias Authify.Accounts
  alias Authify.SCIM.ResourceFormatter
  alias AuthifyWeb.SCIM.PatchOperations

  @bulk_request_schema "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
  @bulk_response_schema "urn:ietf:params:scim:api:messages:2.0:BulkResponse"

  # Maximum operations and payload size (configurable via ServiceProviderConfig)
  @max_operations 1000
  # 1 MB
  @max_payload_size 1_048_576

  @doc """
  POST /scim/v2/Bulk

  Processes multiple SCIM operations in a single request.
  """
  def create(conn, params) do
    organization = conn.assigns[:current_organization]

    case ensure_scim_scope(conn, "scim:write") do
      {:ok, _conn} ->
        # Validate bulk request
        with {:ok, operations} <- validate_bulk_request(conn, params),
             :ok <- validate_max_operations(operations),
             :ok <- validate_payload_size(conn) do
          # Get failOnErrors threshold (default: fail on first error)
          fail_on_errors = parse_int(params["failOnErrors"], 1)

          # Process operations with error tracking
          {responses, _bulk_id_map, _error_count} =
            process_operations(operations, organization, fail_on_errors, conn)

          # Return bulk response
          render_bulk_response(conn, responses)
        else
          {:error, :too_many_operations} ->
            render_scim_error(
              conn,
              413,
              :invalidValue,
              "Too many operations. Maximum is #{@max_operations}"
            )

          {:error, :payload_too_large} ->
            render_scim_error(
              conn,
              413,
              :invalidValue,
              "Payload too large. Maximum is #{@max_payload_size} bytes"
            )

          {:error, reason} ->
            render_scim_error(conn, 400, :invalidSyntax, reason)
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end

  # Validates the bulk request structure
  defp validate_bulk_request(_conn, %{"schemas" => schemas, "Operations" => operations})
       when is_list(operations) do
    if @bulk_request_schema in schemas do
      {:ok, operations}
    else
      {:error, "Invalid schemas. Expected #{@bulk_request_schema}"}
    end
  end

  defp validate_bulk_request(_conn, _params) do
    {:error, "Invalid bulk request. Must include 'schemas' and 'Operations' fields"}
  end

  # Validates operation count doesn't exceed maximum
  defp validate_max_operations(operations) do
    if length(operations) <= @max_operations do
      :ok
    else
      {:error, :too_many_operations}
    end
  end

  # Validates payload size doesn't exceed maximum
  defp validate_payload_size(conn) do
    content_length = Plug.Conn.get_req_header(conn, "content-length") |> List.first()

    case content_length do
      nil ->
        :ok

      size_str ->
        case Integer.parse(size_str) do
          {size, _} when size <= @max_payload_size -> :ok
          _ -> {:error, :payload_too_large}
        end
    end
  end

  # Processes all operations with error tracking and bulkId resolution
  defp process_operations(operations, organization, fail_on_errors, conn) do
    Enum.reduce(operations, {[], %{}, 0}, fn operation, {responses, bulk_id_map, error_count} ->
      # Stop if we've hit the error threshold
      if error_count >= fail_on_errors do
        # Add error response for this operation
        error_response = build_error_response(operation, 412, "failOnErrors threshold reached")
        {responses ++ [error_response], bulk_id_map, error_count}
      else
        # Process the operation
        case process_single_operation(operation, organization, bulk_id_map, conn) do
          {:ok, response, new_bulk_id_map} ->
            {responses ++ [response], Map.merge(bulk_id_map, new_bulk_id_map), error_count}

          {:error, _status, response} ->
            {responses ++ [response], bulk_id_map, error_count + 1}
        end
      end
    end)
  end

  # Processes a single bulk operation
  defp process_single_operation(operation, organization, bulk_id_map, conn) do
    method = String.upcase(operation["method"] || "")
    path = operation["path"]
    bulk_id = operation["bulkId"]
    data = operation["data"]

    # Resolve bulkId references in path and data
    resolved_path = resolve_bulk_id_references(path, bulk_id_map)
    resolved_data = resolve_bulk_id_references(data, bulk_id_map)

    # Parse resource type and ID from path
    case parse_path(resolved_path) do
      {:ok, resource_type, resource_id} ->
        execute_operation(
          method,
          resource_type,
          resource_id,
          resolved_data,
          bulk_id,
          organization,
          conn
        )

      {:error, reason} ->
        {:error, 400, build_error_response(operation, 400, reason)}
    end
  end

  # Parses the path to extract resource type and optional ID
  defp parse_path(path) when is_binary(path) do
    # Remove leading /scim/v2/ or just /
    clean_path = String.replace(path, ~r{^(/scim/v2/|/)}, "")

    case String.split(clean_path, "/") do
      ["Users"] -> {:ok, :user, nil}
      ["Users", id] -> {:ok, :user, id}
      ["Groups"] -> {:ok, :group, nil}
      ["Groups", id] -> {:ok, :group, id}
      _ -> {:error, "Invalid path: #{path}"}
    end
  end

  defp parse_path(_), do: {:error, "Path must be a string"}

  # Executes the operation based on method and resource type
  defp execute_operation("POST", :user, nil, data, bulk_id, organization, conn) do
    # Map SCIM data to user attributes
    attrs = map_scim_to_user_attrs(data)

    case Accounts.create_user_scim(attrs, organization.id) do
      {:ok, user} ->
        user = Authify.Repo.preload(user, :groups)
        base_url = build_base_url(conn)
        resource = ResourceFormatter.format_user(user, base_url)
        location = "#{base_url}/Users/#{user.id}"

        response = %{
          method: "POST",
          bulkId: bulk_id,
          status: "201",
          location: location,
          response: resource
        }

        # Map bulkId to actual resource ID for future references
        bulk_id_map = if bulk_id, do: %{bulk_id => to_string(user.id)}, else: %{}

        {:ok, response, bulk_id_map}

      {:error, changeset} ->
        detail = format_changeset_errors(changeset)

        {:error, 400,
         build_error_response(%{"method" => "POST", "bulkId" => bulk_id}, 400, detail)}
    end
  end

  defp execute_operation("POST", :group, nil, data, bulk_id, organization, conn) do
    attrs = map_scim_to_group_attrs(data)

    case Accounts.create_group_scim(attrs, organization.id) do
      {:ok, group} ->
        group = Authify.Repo.preload(group, :users)
        base_url = build_base_url(conn)
        resource = ResourceFormatter.format_group(group, organization.id, base_url)
        location = "#{base_url}/Groups/#{group.id}"

        response = %{
          method: "POST",
          bulkId: bulk_id,
          status: "201",
          location: location,
          response: resource
        }

        bulk_id_map = if bulk_id, do: %{bulk_id => to_string(group.id)}, else: %{}

        {:ok, response, bulk_id_map}

      {:error, changeset} ->
        detail = format_changeset_errors(changeset)

        {:error, 400,
         build_error_response(%{"method" => "POST", "bulkId" => bulk_id}, 400, detail)}
    end
  end

  defp execute_operation("PUT", :user, id, data, bulk_id, organization, _conn) when id != nil do
    case Accounts.get_user(id) do
      nil ->
        {:error, 404,
         build_error_response(%{"method" => "PUT", "bulkId" => bulk_id}, 404, "User not found")}

      user ->
        if user.organization_id == organization.id do
          attrs = map_scim_to_user_attrs(data)

          case Accounts.update_user_scim(user, attrs) do
            {:ok, _updated_user} ->
              response = %{
                method: "PUT",
                bulkId: bulk_id,
                status: "200"
              }

              {:ok, response, %{}}

            {:error, changeset} ->
              detail = format_changeset_errors(changeset)

              {:error, 400,
               build_error_response(%{"method" => "PUT", "bulkId" => bulk_id}, 400, detail)}
          end
        else
          {:error, 404,
           build_error_response(%{"method" => "PUT", "bulkId" => bulk_id}, 404, "User not found")}
        end
    end
  end

  defp execute_operation("PUT", :group, id, data, bulk_id, organization, _conn) when id != nil do
    case Accounts.get_group(id) do
      nil ->
        {:error, 404,
         build_error_response(%{"method" => "PUT", "bulkId" => bulk_id}, 404, "Group not found")}

      group ->
        if group.organization_id == organization.id do
          attrs = map_scim_to_group_attrs(data)

          case Accounts.update_group_scim(group, attrs) do
            {:ok, _updated_group} ->
              response = %{
                method: "PUT",
                bulkId: bulk_id,
                status: "200"
              }

              {:ok, response, %{}}

            {:error, changeset} ->
              detail = format_changeset_errors(changeset)

              {:error, 400,
               build_error_response(%{"method" => "PUT", "bulkId" => bulk_id}, 400, detail)}
          end
        else
          {:error, 404,
           build_error_response(%{"method" => "PUT", "bulkId" => bulk_id}, 404, "Group not found")}
        end
    end
  end

  defp execute_operation("DELETE", :user, id, _data, bulk_id, organization, _conn)
       when id != nil do
    case Accounts.get_user(id) do
      nil ->
        {:error, 404,
         build_error_response(%{"method" => "DELETE", "bulkId" => bulk_id}, 404, "User not found")}

      user ->
        if user.organization_id == organization.id do
          case Accounts.update_user_scim(user, %{active: false}) do
            {:ok, _user} ->
              response = %{
                method: "DELETE",
                bulkId: bulk_id,
                status: "204"
              }

              {:ok, response, %{}}

            {:error, _} ->
              {:error, 400,
               build_error_response(
                 %{"method" => "DELETE", "bulkId" => bulk_id},
                 400,
                 "Failed to delete user"
               )}
          end
        else
          {:error, 404,
           build_error_response(
             %{"method" => "DELETE", "bulkId" => bulk_id},
             404,
             "User not found"
           )}
        end
    end
  end

  defp execute_operation("DELETE", :group, id, _data, bulk_id, organization, _conn)
       when id != nil do
    case Accounts.get_group(id) do
      nil ->
        {:error, 404,
         build_error_response(
           %{"method" => "DELETE", "bulkId" => bulk_id},
           404,
           "Group not found"
         )}

      group ->
        if group.organization_id == organization.id do
          case Accounts.delete_group(group) do
            {:ok, _group} ->
              response = %{
                method: "DELETE",
                bulkId: bulk_id,
                status: "204"
              }

              {:ok, response, %{}}

            {:error, _} ->
              {:error, 400,
               build_error_response(
                 %{"method" => "DELETE", "bulkId" => bulk_id},
                 400,
                 "Failed to delete group"
               )}
          end
        else
          {:error, 404,
           build_error_response(
             %{"method" => "DELETE", "bulkId" => bulk_id},
             404,
             "Group not found"
           )}
        end
    end
  end

  defp execute_operation("PATCH", :user, id, data, bulk_id, organization, _conn)
       when id != nil do
    case Accounts.get_user(id) do
      nil ->
        {:error, 404,
         build_error_response(%{"method" => "PATCH", "bulkId" => bulk_id}, 404, "User not found")}

      user ->
        if user.organization_id == organization.id do
          operations = data["Operations"] || []

          case PatchOperations.apply_user_patch_operations(user, operations) do
            {:ok, _updated_user} ->
              response = %{
                method: "PATCH",
                bulkId: bulk_id,
                status: "200"
              }

              {:ok, response, %{}}

            {:error, reason} ->
              {:error, 400,
               build_error_response(%{"method" => "PATCH", "bulkId" => bulk_id}, 400, reason)}
          end
        else
          {:error, 404,
           build_error_response(
             %{"method" => "PATCH", "bulkId" => bulk_id},
             404,
             "User not found"
           )}
        end
    end
  end

  defp execute_operation("PATCH", :group, id, data, bulk_id, organization, _conn)
       when id != nil do
    case Accounts.get_group(id) do
      nil ->
        {:error, 404,
         build_error_response(%{"method" => "PATCH", "bulkId" => bulk_id}, 404, "Group not found")}

      group ->
        if group.organization_id == organization.id do
          operations = data["Operations"] || []

          case PatchOperations.apply_group_patch_operations(group, operations, organization) do
            {:ok, _updated_group} ->
              response = %{
                method: "PATCH",
                bulkId: bulk_id,
                status: "200"
              }

              {:ok, response, %{}}

            {:error, reason} ->
              {:error, 400,
               build_error_response(%{"method" => "PATCH", "bulkId" => bulk_id}, 400, reason)}
          end
        else
          {:error, 404,
           build_error_response(
             %{"method" => "PATCH", "bulkId" => bulk_id},
             404,
             "Group not found"
           )}
        end
    end
  end

  defp execute_operation(method, _resource_type, _id, _data, bulk_id, _organization, _conn) do
    {:error, 400,
     build_error_response(
       %{"method" => method, "bulkId" => bulk_id},
       400,
       "Unsupported method: #{method}"
     )}
  end

  # Resolves bulkId references in paths and data
  # Example: /Users/bulkId:user1 -> /Users/123
  defp resolve_bulk_id_references(value, bulk_id_map) when is_binary(value) do
    Enum.reduce(bulk_id_map, value, fn {bulk_id, actual_id}, acc ->
      String.replace(acc, "bulkId:#{bulk_id}", actual_id)
    end)
  end

  defp resolve_bulk_id_references(value, bulk_id_map) when is_map(value) do
    Map.new(value, fn {k, v} ->
      {k, resolve_bulk_id_references(v, bulk_id_map)}
    end)
  end

  defp resolve_bulk_id_references(value, _bulk_id_map), do: value

  # Builds an error response for a failed operation
  defp build_error_response(operation, status, detail) do
    %{
      method: operation["method"],
      bulkId: operation["bulkId"],
      status: to_string(status),
      response: %{
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        status: to_string(status),
        detail: detail
      }
    }
  end

  # Renders the bulk response
  defp render_bulk_response(conn, responses) do
    bulk_response = %{
      schemas: [@bulk_response_schema],
      Operations: responses
    }

    conn
    |> put_resp_content_type("application/scim+json")
    |> json(bulk_response)
  end

  # Helper functions (similar to UsersController and GroupsController)

  defp build_base_url(conn) do
    org_slug = conn.assigns[:current_organization].slug
    "#{AuthifyWeb.Endpoint.url()}/#{org_slug}/scim/v2"
  end

  defp parse_int(nil, default), do: default

  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_int(value, _default) when is_integer(value), do: value
  defp parse_int(_, default), do: default

  # Map SCIM user attributes (similar to UsersController)
  defp map_scim_to_user_attrs(params) when is_map(params) do
    {attrs, username_email} = map_username_field(params)

    attrs
    |> maybe_put(:external_id, params["externalId"])
    |> maybe_put(:first_name, get_in(params, ["name", "givenName"]))
    |> maybe_put(:last_name, get_in(params, ["name", "familyName"]))
    |> maybe_put(:active, params["active"])
    |> Map.put(:emails, build_email_list(params, username_email))
  end

  defp map_scim_to_user_attrs(_), do: %{}

  defp map_username_field(params) do
    case params["userName"] do
      nil ->
        {%{}, nil}

      username when is_binary(username) ->
        if String.contains?(username, "@") do
          {%{}, username}
        else
          {%{username: username}, nil}
        end
    end
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

  # Map SCIM group attributes
  defp map_scim_to_group_attrs(params) when is_map(params) do
    %{}
    |> maybe_put(:name, params["displayName"])
    |> maybe_put(:external_id, params["externalId"])
  end

  defp map_scim_to_group_attrs(_), do: %{}

  defp maybe_put(attrs, _key, nil), do: attrs
  defp maybe_put(attrs, key, value), do: Map.put(attrs, key, value)

  defp format_changeset_errors(changeset) do
    errors =
      Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
        Enum.reduce(opts, msg, fn {key, value}, acc ->
          String.replace(acc, "%{#{key}}", to_string(value))
        end)
      end)

    Enum.map_join(errors, "; ", fn {field, messages} ->
      "#{field}: #{format_messages(messages)}"
    end)
  end

  defp format_messages(messages) when is_list(messages), do: Enum.join(messages, ", ")
  defp format_messages(message), do: to_string(message)
end
