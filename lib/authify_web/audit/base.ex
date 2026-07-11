defmodule AuthifyWeb.Audit.Base do
  @moduledoc """
  Shared helpers for the domain-specific audit logging modules.

  Provides the common `log_event_async/6` entry point plus utilities for
  extracting connection metadata, normalizing values, diffing settings, and
  building audit event attributes from a `Plug.Conn`.
  """

  alias Authify.Accounts.User
  alias Authify.AuditLog
  alias Authify.Repo
  alias Ecto.Changeset
  alias Plug.Conn

  @doc """
  Logs an audit event using the connection assigns to determine actor metadata.
  """
  def log_event_async(conn, event_type, resource_type, resource_id, outcome, metadata \\ %{}) do
    organization = conn.assigns.current_organization
    actor_type = conn.assigns[:actor_type] || :user

    base_attrs = %{
      organization_id: organization.id,
      resource_type: resource_type,
      resource_id: resource_id,
      outcome: outcome,
      ip_address: get_ip_address(conn),
      user_agent: get_user_agent(conn),
      metadata: metadata
    }

    attrs =
      case actor_type do
        :user ->
          user = ensure_user_emails_loaded(conn.assigns.current_user)

          Map.merge(base_attrs, %{
            actor_type: "user",
            actor_id: user.id,
            actor_name: build_user_name(user)
          })

        :application ->
          application = conn.assigns.current_application

          Map.merge(base_attrs, %{
            actor_type: "application",
            actor_id: application.id,
            actor_name: application.name
          })
      end

    AuditLog.log_event_async(event_type, attrs)
  end

  @doc """
  Extracts the client IP address from the connection.
  """
  defdelegate get_ip_address(conn), to: AuthifyWeb.Helpers.ConnHelpers, as: :get_client_ip

  @doc """
  Extracts the user agent from the connection.
  """
  defdelegate get_user_agent(conn), to: AuthifyWeb.Helpers.ConnHelpers

  @doc """
  Converts changeset errors into a flat list of human-readable strings.
  """
  def changeset_errors(%Changeset{} = changeset) do
    changeset
    |> Changeset.traverse_errors(&translate_error/1)
    |> Enum.flat_map(fn {field, messages} ->
      Enum.map(List.wrap(messages), fn message ->
        "#{field} #{message}"
      end)
    end)
  end

  @doc """
  Ensures the user's emails association is loaded.
  """
  def ensure_user_emails_loaded(nil), do: nil

  def ensure_user_emails_loaded(%User{emails: %Ecto.Association.NotLoaded{}} = user) do
    Repo.preload(user, :emails)
  end

  def ensure_user_emails_loaded(%User{emails: emails} = user) when is_list(emails), do: user

  def ensure_user_emails_loaded(%User{} = user), do: Repo.preload(user, :emails)

  @doc """
  Assigns actor and organization assigns from a user struct.
  """
  def assign_actor_from_user(conn, user) do
    user = ensure_user_emails_loaded(user)

    conn
    |> Conn.assign(:actor_type, :user)
    |> Conn.assign(:current_user, user)
    |> Conn.assign(:current_organization, user.organization)
  end

  @doc """
  Ensures the current_organization assign is set.
  """
  def ensure_current_organization(conn, nil), do: conn

  def ensure_current_organization(conn, organization) do
    case conn.assigns[:current_organization] do
      nil -> Conn.assign(conn, :current_organization, organization)
      _ -> conn
    end
  end

  @doc """
  Normalizes an arbitrary value into a JSON-serializable form.
  """
  def normalize_value(nil), do: nil
  def normalize_value(value) when is_boolean(value) or is_number(value), do: value
  def normalize_value(value) when is_binary(value), do: value
  def normalize_value(value) when is_list(value), do: Enum.map(value, &normalize_value/1)

  def normalize_value(%_{} = struct) do
    struct
    |> Map.from_struct()
    |> normalize_value()
  end

  def normalize_value(value) when is_map(value) do
    value
    |> Enum.map(fn {key, val} -> {to_string(key), normalize_value(val)} end)
    |> Enum.into(%{})
  end

  def normalize_value(value), do: inspect(value)

  @doc """
  Normalizes errors into a flat list of strings.
  """
  def normalize_errors(errors) when is_binary(errors), do: [errors]
  def normalize_errors(errors) when is_list(errors), do: Enum.map(errors, &to_string/1)
  def normalize_errors(%Changeset{} = changeset), do: changeset_errors(changeset)
  def normalize_errors(nil), do: []
  def normalize_errors(other), do: [inspect(other)]

  @doc """
  Puts `key` into `map` unless `value` is an empty list.
  """
  def maybe_put(map, _key, []), do: map
  def maybe_put(map, key, value), do: Map.put(map, key, value)

  @doc """
  Merges `extra` into `map` when it is a map, stringifying keys.
  """
  def maybe_merge(map, nil), do: map

  def maybe_merge(map, extra) when is_map(extra) do
    Map.merge(map, stringify_keys(extra))
  end

  def maybe_merge(map, _extra), do: map

  @doc """
  Converts a kwarg value into a `MapSet`, falling back to `default`.
  """
  def kwargs_to_set(nil, default), do: default
  def kwargs_to_set(%MapSet{} = set, _default), do: set

  def kwargs_to_set(values, _default) when is_list(values) do
    values
    |> Enum.map(&to_string/1)
    |> MapSet.new()
  end

  def kwargs_to_set(_other, default), do: default

  @doc """
  Masks a value when its field is considered sensitive.
  """
  def mask_sensitive(field, value, sensitive_fields) do
    if MapSet.member?(sensitive_fields, field) and not is_nil(value) and value != "" do
      "[FILTERED]"
    else
      value
    end
  end

  @doc """
  Computes a list of change maps between two settings maps.
  """
  def diff_settings(old_settings, new_settings, sensitive_fields) do
    keys =
      Map.keys(old_settings)
      |> Enum.concat(Map.keys(new_settings))
      |> Enum.uniq()

    keys
    |> Enum.reduce([], fn key, acc ->
      old_val = Map.get(old_settings, key)
      new_val = Map.get(new_settings, key)

      if old_val == new_val do
        acc
      else
        field = to_string(key)

        change = %{
          "field" => field,
          "old" => mask_sensitive(field, normalize_value(old_val), sensitive_fields),
          "new" => mask_sensitive(field, normalize_value(new_val), sensitive_fields)
        }

        [change | acc]
      end
    end)
    |> Enum.reverse()
  end

  @doc """
  Computes a list of change maps between two structs for the given fields.
  """
  def diff_struct_fields(old_struct, new_struct, fields, sensitive_fields) do
    old_map = extract_fields(old_struct, fields)
    new_map = extract_fields(new_struct, fields)

    fields
    |> Enum.reduce([], fn field, acc ->
      old_val = Map.get(old_map, field)
      new_val = Map.get(new_map, field)

      if old_val == new_val do
        acc
      else
        field_str = to_string(field)

        change = %{
          "field" => field_str,
          "old" => mask_sensitive(field_str, normalize_value(old_val), sensitive_fields),
          "new" => mask_sensitive(field_str, normalize_value(new_val), sensitive_fields)
        }

        [change | acc]
      end
    end)
    |> Enum.reverse()
  end

  @doc """
  Extracts the given fields from a struct or map.
  """
  def extract_fields(%_{} = struct, fields) do
    struct
    |> Map.from_struct()
    |> extract_fields(fields)
  end

  def extract_fields(map, fields) when is_map(map) do
    Map.take(map, fields)
  end

  @doc """
  Builds a display name for a user.
  """
  def build_user_name(user) do
    cond do
      user.first_name && user.last_name -> "#{user.first_name} #{user.last_name}"
      user.first_name -> user.first_name
      user.last_name -> user.last_name
      true -> User.get_primary_email_value(user)
    end
  end

  defp stringify_keys(map) do
    map
    |> Enum.map(fn {key, value} -> {to_string(key), normalize_value(value)} end)
    |> Enum.into(%{})
  end

  defp translate_error({msg, opts}) do
    Enum.reduce(opts, msg, fn {key, value}, acc ->
      String.replace(acc, "%{#{key}}", to_string(value))
    end)
  end
end
