defmodule AuthifyWeb.SCIM.BulkController do
  @moduledoc """
  SCIM 2.0 Bulk operations endpoint per RFC 7644 Section 3.7.

  Enables clients to send multiple resource operations in a single request.
  Supports bulkId references for dependent operations and configurable error handling.
  """

  use AuthifyWeb.SCIM.BaseController

  alias Authify.Accounts
  alias Authify.SCIM.ResourceFormatter
  alias AuthifyWeb.Helpers.AuditHelper
  alias AuthifyWeb.SCIM.{Helpers, Mappers, PatchOperations}

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
          fail_on_errors = Helpers.parse_int(params["failOnErrors"], 1)

          # Log bulk operation started
          log_bulk_start(conn, organization, length(operations), fail_on_errors)

          # Process operations with error tracking
          {responses, _bulk_id_map, error_count} =
            process_operations(operations, organization, fail_on_errors, conn)

          # Log bulk operation completed
          log_bulk_completion(conn, organization, responses, error_count)

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
    attrs = Mappers.map_user_attrs(data)

    case Accounts.create_user_scim(attrs, organization.id) do
      {:ok, user} ->
        user = Authify.Repo.preload(user, :groups)
        base_url = Helpers.build_base_url(conn)
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
        detail = Helpers.format_changeset_errors(changeset)

        {:error, 400,
         build_error_response(%{"method" => "POST", "bulkId" => bulk_id}, 400, detail)}
    end
  end

  defp execute_operation("POST", :group, nil, data, bulk_id, organization, conn) do
    attrs = Mappers.map_group_attrs(data)

    case Accounts.create_group_scim(attrs, organization.id) do
      {:ok, group} ->
        group = Authify.Repo.preload(group, :users)
        base_url = Helpers.build_base_url(conn)
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
        detail = Helpers.format_changeset_errors(changeset)

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
        case Helpers.validate_resource_organization(user, organization) do
          :ok ->
            attrs = Mappers.map_user_attrs(data)

            case Accounts.update_user_scim(user, attrs) do
              {:ok, _updated_user} ->
                response = %{
                  method: "PUT",
                  bulkId: bulk_id,
                  status: "200"
                }

                {:ok, response, %{}}

              {:error, changeset} ->
                detail = Helpers.format_changeset_errors(changeset)

                {:error, 400,
                 build_error_response(%{"method" => "PUT", "bulkId" => bulk_id}, 400, detail)}
            end

          {:error, :not_found} ->
            {:error, 404,
             build_error_response(
               %{"method" => "PUT", "bulkId" => bulk_id},
               404,
               "User not found"
             )}
        end
    end
  end

  defp execute_operation("PUT", :group, id, data, bulk_id, organization, _conn) when id != nil do
    case Accounts.get_group(id) do
      nil ->
        {:error, 404,
         build_error_response(%{"method" => "PUT", "bulkId" => bulk_id}, 404, "Group not found")}

      group ->
        case Helpers.validate_resource_organization(group, organization) do
          :ok ->
            attrs = Mappers.map_group_attrs(data)

            case Accounts.update_group_scim(group, attrs) do
              {:ok, _updated_group} ->
                response = %{
                  method: "PUT",
                  bulkId: bulk_id,
                  status: "200"
                }

                {:ok, response, %{}}

              {:error, changeset} ->
                detail = Helpers.format_changeset_errors(changeset)

                {:error, 400,
                 build_error_response(%{"method" => "PUT", "bulkId" => bulk_id}, 400, detail)}
            end

          {:error, :not_found} ->
            {:error, 404,
             build_error_response(
               %{"method" => "PUT", "bulkId" => bulk_id},
               404,
               "Group not found"
             )}
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
        case Helpers.validate_resource_organization(user, organization) do
          :ok ->
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

          {:error, :not_found} ->
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
        case Helpers.validate_resource_organization(group, organization) do
          :ok ->
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

          {:error, :not_found} ->
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
        case Helpers.validate_resource_organization(user, organization) do
          :ok ->
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

          {:error, :not_found} ->
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
        case Helpers.validate_resource_organization(group, organization) do
          :ok ->
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

          {:error, :not_found} ->
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

  # Logs bulk operation start
  defp log_bulk_start(conn, organization, operations_count, fail_on_errors) do
    AuditHelper.log_event_async(
      conn,
      :scim_bulk_operation_started,
      "bulk_operation",
      nil,
      "success",
      %{
        "organization_slug" => organization.slug,
        "operations_count" => operations_count,
        "fail_on_errors" => fail_on_errors
      }
    )
  end

  # Logs bulk operation completion
  defp log_bulk_completion(conn, organization, responses, error_count) do
    successful_count = length(responses) - error_count

    AuditHelper.log_event_async(
      conn,
      :scim_bulk_operation_completed,
      "bulk_operation",
      nil,
      if(error_count == 0, do: "success", else: "failure"),
      %{
        "organization_slug" => organization.slug,
        "operations_count" => length(responses),
        "successful_count" => successful_count,
        "error_count" => error_count
      }
    )
  end
end
