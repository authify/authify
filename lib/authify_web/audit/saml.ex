defmodule AuthifyWeb.Audit.SAML do
  @moduledoc """
  Audit logging for SAML assertion and single logout events.
  """

  alias Authify.AuditLog
  alias AuthifyWeb.Audit.Base

  @doc """
  Logs a SAML assertion issuance event.
  """
  def log_assertion_issued(conn, organization, current_user, sp, saml_session) do
    AuditLog.log_event_async(:saml_assertion_issued, %{
      organization_id: organization.id,
      actor_type: "user",
      actor_id: current_user.id,
      actor_name: Base.build_user_name(current_user),
      resource_type: "saml_assertion",
      resource_id: saml_session.id,
      outcome: "success",
      ip_address: Base.get_ip_address(conn),
      user_agent: Base.get_user_agent(conn),
      metadata: %{
        service_provider_id: sp.id,
        service_provider_name: sp.name,
        entity_id: sp.entity_id,
        session_id: saml_session.session_id,
        relay_state: saml_session.relay_state
      }
    })
  end

  @doc """
  Logs a SAML single logout completion event.
  """
  def log_slo_completed(conn, organization, current_user, sp) do
    AuditLog.log_event_async(:saml_slo_completed, %{
      organization_id: organization.id,
      actor_type: "user",
      actor_id: current_user.id,
      actor_name: Base.build_user_name(current_user),
      outcome: "success",
      ip_address: Base.get_ip_address(conn),
      user_agent: Base.get_user_agent(conn),
      metadata: %{
        service_provider_id: sp.id,
        service_provider_name: sp.name,
        entity_id: sp.entity_id,
        initiator: "service_provider"
      }
    })
  end

  @doc """
  Logs a generic SAML service provider lifecycle event.
  """
  def log_saml_provider_event(conn, event_type, service_provider, opts \\ []) do
    metadata =
      %{
        "service_provider_id" => service_provider.id,
        "service_provider_name" => service_provider.name,
        "entity_id" => service_provider.entity_id,
        "acs_url" => service_provider.acs_url,
        "organization_slug" => conn.assigns.current_organization.slug
      }
      |> Base.maybe_merge(opts[:extra_metadata])

    Base.log_event_async(
      conn,
      event_type,
      opts[:resource_type] || "saml_service_provider",
      opts[:resource_id] || service_provider.id,
      opts[:outcome] || "success",
      metadata
    )
  end
end
