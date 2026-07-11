defmodule AuthifyWeb.Audit.Sessions do
  @moduledoc """
  Audit logging for session and login lifecycle events.
  """

  alias Authify.AuditLog
  alias AuthifyWeb.Audit.Base

  @doc """
  Logs a successful login event.
  """
  def log_login_success(conn, organization, user) do
    AuditLog.log_event_async(:login_success, %{
      organization_id: organization.id,
      actor_type: "user",
      actor_id: user.id,
      actor_name: Base.build_user_name(user),
      outcome: "success",
      ip_address: Base.get_ip_address(conn),
      user_agent: Base.get_user_agent(conn)
    })
  end

  @doc """
  Logs a failed login attempt.
  """
  def log_login_failure(conn, organization, email, reason) do
    AuditLog.log_event_async(:login_failure, %{
      organization_id: organization.id,
      actor_type: "user",
      actor_name: email,
      outcome: "failure",
      ip_address: Base.get_ip_address(conn),
      user_agent: Base.get_user_agent(conn),
      metadata: %{reason: to_string(reason), attempted_email: email}
    })
  end

  @doc """
  Logs a logout event.
  """
  def log_logout(conn, current_user, slo_complete) do
    AuditLog.log_event_async(:logout, %{
      organization_id: current_user.organization_id,
      actor_type: "user",
      actor_id: current_user.id,
      actor_name: Base.build_user_name(current_user),
      outcome: "success",
      ip_address: Base.get_ip_address(conn),
      user_agent: Base.get_user_agent(conn),
      metadata: %{saml_slo: slo_complete == "true"}
    })
  end
end
