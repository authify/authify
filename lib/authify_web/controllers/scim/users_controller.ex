defmodule AuthifyWeb.SCIM.UsersController do
  @moduledoc """
  SCIM 2.0 Users resource endpoint per RFC 7644 Section 3.

  Provides CRUD operations for user provisioning from external systems.
  """

  use AuthifyWeb.SCIM.BaseController

  alias Authify.Accounts
  alias Authify.SCIM.ResourceFormatter

  @doc """
  GET /scim/v2/Users

  Lists users with optional filtering, sorting, and pagination.
  """
  def index(conn, params) do
    organization = conn.assigns[:current_organization]

    # Check scope
    case ensure_scim_scope(conn, "scim:users:read") do
      {:ok, _conn} ->
        # Parse pagination params (SCIM uses 1-based indexing)
        start_index = parse_int(params["startIndex"], 1)
        count = min(parse_int(params["count"], 25), 100)
        page = div(start_index - 1, count) + 1

        # Build query options
        opts = [
          page: page,
          per_page: count,
          filter: params["filter"],
          sort_by: params["sortBy"],
          sort_order: params["sortOrder"]
        ]

        # Fetch users and count
        case Accounts.list_users_scim(organization.id, opts) do
          {:ok, users} ->
            case Accounts.count_users_scim(organization.id, filter: params["filter"]) do
              {:ok, total} ->
                base_url = build_base_url(conn)

                resources =
                  Enum.map(users, fn user ->
                    ResourceFormatter.format_user(user, base_url)
                  end)

                render_scim_list(conn, resources, total, start_index, count, :user)

              {:error, reason} ->
                render_scim_error(conn, 400, :invalid_filter, "Invalid filter: #{reason}")
            end

          {:error, reason} ->
            render_scim_error(conn, 400, :invalid_filter, "Invalid filter: #{reason}")
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end

  @doc """
  GET /scim/v2/Users/:id

  Returns a single user by ID.
  """
  def show(conn, %{"id" => id}) do
    organization = conn.assigns[:current_organization]

    case ensure_scim_scope(conn, "scim:users:read") do
      {:ok, _conn} ->
        case Accounts.get_user(id) do
          nil ->
            render_scim_error(conn, 404, :no_target, "User not found")

          user ->
            # Verify user belongs to organization (multi-tenant isolation)
            if user.organization_id == organization.id do
              # Preload emails and groups for SCIM response
              user = Authify.Repo.preload(user, [:emails, :groups])
              base_url = build_base_url(conn)
              resource = ResourceFormatter.format_user(user, base_url)
              render_scim_resource(conn, resource)
            else
              render_scim_error(conn, 404, :no_target, "User not found")
            end
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end

  @doc """
  POST /scim/v2/Users

  Creates a new user from SCIM data.
  """
  def create(conn, params) do
    organization = conn.assigns[:current_organization]

    case ensure_scim_scope(conn, "scim:users:write") do
      {:ok, _conn} ->
        # Map SCIM attributes to Authify user attributes
        attrs = map_scim_to_user_attrs(params)

        # Create user via SCIM-specific function
        case Accounts.create_user_scim(attrs, organization.id) do
          {:ok, user} ->
            render_created_user(conn, user)

          {:error, %Ecto.Changeset{} = changeset} ->
            handle_create_error(conn, changeset, attrs)

          {:error, reason} ->
            render_scim_error(conn, 400, :invalid_value, "Failed to create user: #{reason}")
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end

  defp render_created_user(conn, user) do
    user = Authify.Repo.preload(user, :groups)
    base_url = build_base_url(conn)
    resource = ResourceFormatter.format_user(user, base_url)

    conn
    |> put_resp_header("location", "#{base_url}/Users/#{user.id}")
    |> render_scim_resource(resource, status: 201)
  end

  defp handle_create_error(conn, changeset, attrs) do
    errors = Ecto.Changeset.traverse_errors(changeset, & &1)

    cond do
      Map.has_key?(errors, :external_id) ->
        render_scim_error(
          conn,
          409,
          :uniqueness,
          "User with externalId '#{attrs[:external_id]}' already exists"
        )

      has_email_uniqueness_error?(changeset) ->
        email_value = get_duplicate_email_value(changeset)

        render_scim_error(
          conn,
          409,
          :uniqueness,
          "User with email '#{email_value}' already exists"
        )

      Map.has_key?(errors, :username) ->
        render_scim_error(
          conn,
          409,
          :uniqueness,
          "User with userName '#{attrs[:username]}' already exists"
        )

      true ->
        detail = format_changeset_errors(changeset)
        render_scim_error(conn, 400, :invalid_value, detail)
    end
  end

  @doc """
  PUT /scim/v2/Users/:id

  Replaces an existing user (full update).
  """
  def update(conn, %{"id" => id} = params) do
    organization = conn.assigns[:current_organization]

    case ensure_scim_scope(conn, "scim:users:write") do
      {:ok, _conn} ->
        case Accounts.get_user(id) do
          nil ->
            render_scim_error(conn, 404, :no_target, "User not found")

          user ->
            do_update_user(conn, user, organization, params)
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end

  @doc """
  PATCH /scim/v2/Users/:id

  Partially updates a user using SCIM PATCH operations.
  """
  def patch(conn, %{"id" => id} = params) do
    organization = conn.assigns[:current_organization]

    case ensure_scim_scope(conn, "scim:users:write") do
      {:ok, _conn} ->
        case Accounts.get_user(id) do
          nil ->
            render_scim_error(conn, 404, :no_target, "User not found")

          user ->
            if user.organization_id == organization.id do
              # Parse PATCH operations
              operations = params["Operations"] || []

              case apply_patch_operations(user, operations) do
                {:ok, updated_user} ->
                  updated_user = Authify.Repo.preload(updated_user, :groups)
                  base_url = build_base_url(conn)
                  resource = ResourceFormatter.format_user(updated_user, base_url)
                  render_scim_resource(conn, resource)

                {:error, reason} ->
                  render_scim_error(conn, 400, :invalid_value, reason)
              end
            else
              render_scim_error(conn, 404, :no_target, "User not found")
            end
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end

  # Private helper for update to reduce nesting
  defp do_update_user(conn, user, organization, params) do
    if user.organization_id == organization.id do
      # Map SCIM attributes to Authify user attributes
      attrs = map_scim_to_user_attrs(params)

      # Validate immutable fields
      if attrs[:external_id] && attrs[:external_id] != user.external_id do
        render_scim_error(
          conn,
          400,
          :mutability,
          "Attribute 'externalId' is immutable and cannot be modified"
        )
      else
        case Accounts.update_user_scim(user, attrs) do
          {:ok, updated_user} ->
            updated_user = Authify.Repo.preload(updated_user, :groups)
            base_url = build_base_url(conn)
            resource = ResourceFormatter.format_user(updated_user, base_url)
            render_scim_resource(conn, resource)

          {:error, %Ecto.Changeset{} = changeset} ->
            detail = format_changeset_errors(changeset)
            render_scim_error(conn, 400, :invalid_value, detail)

          {:error, reason} ->
            render_scim_error(conn, 400, :invalid_value, "Failed to update user: #{reason}")
        end
      end
    else
      render_scim_error(conn, 404, :no_target, "User not found")
    end
  end

  @doc """
  DELETE /scim/v2/Users/:id

  Soft deletes a user (sets active=false).
  """
  def delete(conn, %{"id" => id}) do
    organization = conn.assigns[:current_organization]

    case ensure_scim_scope(conn, "scim:users:write") do
      {:ok, _conn} ->
        case Accounts.get_user(id) do
          nil ->
            render_scim_error(conn, 404, :no_target, "User not found")

          user ->
            if user.organization_id == organization.id do
              case Accounts.update_user_scim(user, %{active: false}) do
                {:ok, _user} ->
                  send_resp(conn, 204, "")

                {:error, reason} ->
                  render_scim_error(conn, 400, :invalid_value, "Failed to delete user: #{reason}")
              end
            else
              render_scim_error(conn, 404, :no_target, "User not found")
            end
        end

      {:error, :unauthorized} ->
        render_scim_error(conn, 403, :sensitive, "Insufficient scope")
    end
  end

  # Private functions

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

  # Maps SCIM user attributes to Authify user attributes
  defp map_scim_to_user_attrs(params) do
    %{}
    |> map_username_field(params)
    |> map_external_id(params)
    |> map_name_fields(params)
    |> map_email_fields(params)
    |> map_active_field(params)
  end

  defp map_username_field(attrs, params) do
    case params["userName"] do
      nil ->
        {attrs, nil}

      username when is_binary(username) ->
        if String.contains?(username, "@") do
          {attrs, username}
        else
          {Map.put(attrs, :username, username), nil}
        end
    end
  end

  defp map_external_id({attrs, username_email}, params) do
    attrs =
      if params["externalId"],
        do: Map.put(attrs, :external_id, params["externalId"]),
        else: attrs

    {attrs, username_email}
  end

  defp map_name_fields({attrs, username_email}, params) do
    attrs =
      attrs
      |> maybe_put(:first_name, get_in(params, ["name", "givenName"]))
      |> maybe_put(:last_name, get_in(params, ["name", "familyName"]))

    {attrs, username_email}
  end

  defp map_email_fields({attrs, username_email}, params) do
    emails = build_email_list(params, username_email)
    Map.put(attrs, :emails, emails)
  end

  defp map_active_field(attrs, params) do
    if Map.has_key?(params, "active"),
      do: Map.put(attrs, :active, params["active"]),
      else: attrs
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

  defp maybe_put(attrs, _key, nil), do: attrs
  defp maybe_put(attrs, key, value), do: Map.put(attrs, key, value)

  # Applies SCIM PATCH operations to a user
  defp apply_patch_operations(user, operations) do
    Enum.reduce_while(operations, {:ok, user}, fn op, {:ok, current_user} ->
      case apply_single_patch_op(current_user, op) do
        {:ok, updated_user} -> {:cont, {:ok, updated_user}}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  defp apply_single_patch_op(user, %{"op" => "replace", "path" => path, "value" => value}) do
    case normalize_path(path) do
      "active" ->
        Accounts.update_user_scim(user, %{active: value})

      "name.givenname" ->
        Accounts.update_user_scim(user, %{first_name: value})

      "name.familyname" ->
        Accounts.update_user_scim(user, %{last_name: value})

      _ ->
        {:error, "Unsupported PATCH path: #{path}"}
    end
  end

  defp apply_single_patch_op(user, %{"op" => "replace", "value" => value}) when is_map(value) do
    # Replace operation with no path - update entire resource
    attrs = map_scim_to_user_attrs(value)
    Accounts.update_user_scim(user, attrs)
  end

  defp apply_single_patch_op(_user, op) do
    {:error, "Unsupported PATCH operation: #{op["op"]}"}
  end

  defp normalize_path(nil), do: nil
  defp normalize_path(path) when is_binary(path), do: String.downcase(path)

  defp format_changeset_errors(changeset) do
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

  # Format error messages, handling both simple strings and nested errors from associations
  defp format_error_messages(messages) when is_list(messages) do
    messages
    |> Enum.map_join(", ", &format_error_message/1)
  end

  defp format_error_messages(message), do: format_error_message(message)

  defp format_error_message(msg) when is_binary(msg), do: msg

  defp format_error_message(msg) when is_map(msg) do
    # Nested error from association (e.g., emails)
    Enum.map_join(msg, "; ", fn {field, messages} ->
      "#{field}: #{format_error_messages(messages)}"
    end)
  end

  defp format_error_message(msg), do: inspect(msg)

  # Check if changeset has a uniqueness error on any email
  defp has_email_uniqueness_error?(changeset) do
    case Ecto.Changeset.get_change(changeset, :emails) do
      nil ->
        false

      email_changesets when is_list(email_changesets) ->
        Enum.any?(email_changesets, fn
          %Ecto.Changeset{errors: errors} ->
            Enum.any?(errors, fn
              {:value, {_msg, [constraint: :unique, constraint_name: _]}} -> true
              _ -> false
            end)

          _ ->
            false
        end)

      _ ->
        false
    end
  end

  # Get the email value that caused the uniqueness error
  defp get_duplicate_email_value(changeset) do
    case Ecto.Changeset.get_change(changeset, :emails) do
      nil ->
        "unknown"

      email_changesets when is_list(email_changesets) ->
        email_changeset =
          Enum.find(email_changesets, fn
            %Ecto.Changeset{errors: errors} ->
              Enum.any?(errors, fn
                {:value, {_msg, [constraint: :unique, constraint_name: _]}} -> true
                _ -> false
              end)

            _ ->
              false
          end)

        case email_changeset do
          %Ecto.Changeset{} ->
            Ecto.Changeset.get_field(email_changeset, :value, "unknown")

          _ ->
            "unknown"
        end

      _ ->
        "unknown"
    end
  end
end
