defmodule AuthifyWeb.Audit.Certificates do
  @moduledoc """
  Audit logging for certificate lifecycle events.
  """

  alias AuthifyWeb.Audit.Base

  @doc """
  Logs certificate lifecycle events (creation, activation, deactivation, deletion).
  """
  def log_certificate_event(conn, event_type, certificate, opts \\ []) do
    metadata =
      %{
        "certificate_id" => certificate.id,
        "certificate_name" => certificate.name,
        "usage" => certificate.usage,
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> maybe_put_generated(opts[:generated])
      |> maybe_put_previous_state(opts[:previous_state])
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      event_type,
      opts[:resource_type] || "certificate",
      opts[:resource_id] || certificate.id,
      opts[:outcome] || "success",
      metadata
    )
  end

  @doc """
  Logs failed certificate lifecycle attempts with error details.
  """
  def log_certificate_failure(conn, event_type, errors, opts \\ []) do
    certificate = opts[:certificate]

    metadata =
      %{
        "errors" => Base.normalize_errors(errors),
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> Base.maybe_merge(opts[:extra_metadata])
      |> maybe_attach_certificate(certificate)

    Base.log_event_async(
      conn,
      event_type,
      opts[:resource_type] || "certificate",
      opts[:resource_id] || maybe_certificate_id(certificate),
      "failure",
      metadata
    )
  end

  @doc """
  Logs personal access token lifecycle events (creation, deletion, etc.).
  """
  def log_personal_access_token_event(conn, event_type, token, opts \\ []) do
    metadata =
      %{
        "personal_access_token_id" => token.id,
        "personal_access_token_name" => token.name,
        "user_id" => token.user_id,
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> Base.maybe_put("description", token.description)
      |> Base.maybe_put("scopes", personal_access_token_scopes(token))
      |> Base.maybe_put("expires_at", Base.normalize_value(token.expires_at))
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      event_type,
      opts[:resource_type] || "personal_access_token",
      opts[:resource_id] || token.id,
      opts[:outcome] || "success",
      metadata
    )
  end

  @doc """
  Logs failed personal access token operations with error details.
  """
  def log_personal_access_token_failure(conn, event_type, errors, opts \\ []) do
    token = opts[:personal_access_token]

    metadata =
      %{
        "errors" => Base.normalize_errors(errors),
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> Base.maybe_merge(opts[:extra_metadata])
      |> maybe_attach_personal_access_token(token)

    Base.log_event_async(
      conn,
      event_type,
      opts[:resource_type] || "personal_access_token",
      opts[:resource_id] || maybe_personal_access_token_id(token),
      "failure",
      metadata
    )
  end

  defp maybe_put_generated(map, nil), do: map
  defp maybe_put_generated(map, value), do: Map.put(map, "generated", value)

  defp maybe_put_previous_state(map, nil), do: map

  defp maybe_put_previous_state(map, value) do
    Map.put(map, "previous_state", Base.normalize_value(value))
  end

  defp maybe_attach_certificate(map, nil), do: map

  defp maybe_attach_certificate(map, certificate) do
    map
    |> Map.put("certificate_id", certificate.id)
    |> Map.put("certificate_name", certificate.name)
    |> maybe_put_usage(certificate.usage)
  end

  defp maybe_put_usage(map, nil), do: map
  defp maybe_put_usage(map, usage), do: Map.put(map, "usage", usage)

  defp maybe_certificate_id(nil), do: nil
  defp maybe_certificate_id(%{id: id}), do: id

  defp maybe_attach_personal_access_token(map, nil), do: map

  defp maybe_attach_personal_access_token(map, token) do
    map
    |> Map.put("personal_access_token_id", token.id)
    |> Map.put("personal_access_token_name", token.name)
    |> Base.maybe_put("user_id", token.user_id)
    |> Base.maybe_put("description", token.description)
    |> Base.maybe_put("scopes", personal_access_token_scopes(token))
    |> Base.maybe_put("expires_at", Base.normalize_value(token.expires_at))
  end

  defp maybe_personal_access_token_id(nil), do: nil
  defp maybe_personal_access_token_id(%{id: id}), do: id

  defp personal_access_token_scopes(%Authify.Accounts.PersonalAccessToken{} = token) do
    case Authify.Accounts.PersonalAccessToken.scopes_list(token) do
      [] -> nil
      scopes -> scopes
    end
  end

  defp personal_access_token_scopes(_), do: nil
end
