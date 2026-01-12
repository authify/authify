defmodule AuthifyWeb.SAMLController do
  use AuthifyWeb, :controller

  alias Authify.AuditLog
  alias Authify.SAML

  # Helper to escape HTML and convert to string
  defp html_escape_to_string(value) when is_binary(value) do
    {:safe, iodata} = Phoenix.HTML.html_escape(value)
    IO.iodata_to_binary(iodata)
  end

  @doc """
  SAML IdP Metadata endpoint.
  Returns XML metadata describing this IdP's capabilities.
  """
  def metadata(conn, _params) do
    # Get current organization from context (if available, otherwise use global)
    organization = conn.assigns[:current_organization]

    case SAML.generate_metadata(organization) do
      {:ok, metadata_xml} ->
        conn
        |> put_resp_content_type("application/samlmetadata+xml")
        |> send_resp(200, metadata_xml)

      {:error, reason} ->
        render_saml_error(conn, "Failed to generate metadata: #{reason}")
    end
  end

  @doc """
  SAML SSO endpoint.
  Handles incoming SAML authentication requests from Service Providers.
  """
  def sso(conn, params) do
    case handle_sso_request(conn, params) do
      {:ok, :redirect_to_login, saml_session} ->
        # User not authenticated, redirect to login with SAML session context
        organization = conn.assigns.current_organization

        login_url =
          "/login?" <>
            URI.encode_query(%{
              "saml_session" => saml_session.session_id,
              "return_to" => "/#{organization.slug}/saml/continue/#{saml_session.session_id}"
            })

        redirect(conn, to: login_url)

      {:ok, :show_consent, saml_session, service_provider} ->
        # User authenticated, show consent screen
        render_saml_consent(conn, saml_session, service_provider)

      {:error, error} ->
        render_saml_error(conn, error)
    end
  end

  @doc """
  SAML SSO continuation endpoint.
  Handles SAML flow after user authentication.
  """
  def continue(conn, %{"session_id" => session_id}) do
    current_user = Authify.Guardian.Plug.current_resource(conn)
    organization = conn.assigns.current_organization

    with {:ok, current_user} <- verify_user_authenticated(conn, current_user),
         {:ok, saml_session} <- get_valid_saml_session(session_id),
         :ok <- validate_session_ownership(saml_session, current_user, organization),
         {:ok, updated_session} <- ensure_session_has_user(saml_session, current_user),
         {:ok, form_html} <- generate_and_send_response(conn, updated_session, current_user) do
      log_saml_assertion_issued(conn, organization, current_user, updated_session)

      conn
      |> put_resp_content_type("text/html")
      |> send_resp(200, form_html)
    else
      {:error, :not_authenticated, return_path} ->
        redirect(conn, to: "/login?return_to=#{URI.encode(return_path)}")

      {:error, :invalid_session} ->
        render_saml_error(conn, "Invalid or expired SAML session")

      {:error, :access_denied} ->
        render_saml_error(conn, "Access denied: session does not belong to current user")

      {:error, error} ->
        render_saml_error(conn, error)
    end
  end

  defp verify_user_authenticated(conn, nil) do
    {:error, :not_authenticated, current_path(conn)}
  end

  defp verify_user_authenticated(_conn, current_user), do: {:ok, current_user}

  defp get_valid_saml_session(session_id) do
    case SAML.get_session(session_id) do
      %SAML.Session{service_provider: sp} = session when not is_nil(sp) ->
        {:ok, session}

      _ ->
        {:error, :invalid_session}
    end
  end

  defp validate_session_ownership(saml_session, current_user, organization) do
    sp = saml_session.service_provider

    cond do
      sp.organization_id != organization.id ->
        {:error, :invalid_session}

      saml_session.user_id != current_user.id and saml_session.user_id != nil ->
        {:error, :access_denied}

      true ->
        :ok
    end
  end

  defp ensure_session_has_user(saml_session, current_user) do
    if saml_session.user_id == nil do
      subject_id = SAML.Session.generate_subject_id(current_user, saml_session.service_provider)

      SAML.update_session(saml_session, %{
        user_id: current_user.id,
        subject_id: subject_id
      })
    else
      {:ok, saml_session}
    end
  end

  defp log_saml_assertion_issued(conn, organization, current_user, saml_session) do
    sp = saml_session.service_provider

    AuditLog.log_event_async(:saml_assertion_issued, %{
      organization_id: organization.id,
      actor_type: "user",
      actor_id: current_user.id,
      actor_name: "#{current_user.first_name} #{current_user.last_name}",
      resource_type: "saml_assertion",
      resource_id: saml_session.id,
      outcome: "success",
      ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
      user_agent: Plug.Conn.get_req_header(conn, "user-agent") |> List.first(),
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
  SAML Single Logout endpoint.
  Handles logout requests from Service Providers.
  """
  def slo(conn, params) do
    case params do
      %{"SAMLRequest" => saml_request} ->
        # SP-initiated logout
        handle_slo_request(conn, saml_request, params)

      %{"SAMLResponse" => _saml_response} ->
        # Response to IdP-initiated logout
        handle_slo_response(conn, params)

      _ ->
        # No SAML request/response, treat as local logout
        handle_local_logout(conn)
    end
  end

  # Private helper functions

  defp handle_sso_request(conn, params) do
    # Extract SAML request (could be in SAMLRequest parameter or RelayState)
    saml_request = params["SAMLRequest"]
    relay_state = params["RelayState"]
    organization = conn.assigns.current_organization

    if saml_request do
      case SAML.parse_saml_request(saml_request) do
        {:ok, request_info} ->
          case SAML.get_service_provider_by_entity_id(request_info.issuer, organization) do
            %SAML.ServiceProvider{} = sp ->
              create_saml_session(conn, request_info, sp, relay_state)

            nil ->
              {:error, "Unknown service provider: #{request_info.issuer}"}
          end

        {:error, reason} ->
          {:error, "Invalid SAML request: #{reason}"}
      end
    else
      {:error, "Missing SAML request"}
    end
  end

  defp create_saml_session(conn, request_info, service_provider, relay_state) do
    session_id = SAML.Session.generate_session_id()
    current_user = Authify.Guardian.Plug.current_resource(conn)

    # Set default expiration (1 hour from now)
    expires_at = DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.truncate(:second)

    session_attrs = %{
      session_id: session_id,
      request_id: request_info.request_id,
      relay_state: relay_state,
      service_provider_id: service_provider.id,
      issued_at: DateTime.utc_now() |> DateTime.truncate(:second),
      expires_at: expires_at
    }

    session_attrs =
      if current_user do
        subject_id = SAML.Session.generate_subject_id(current_user, service_provider)

        session_attrs
        |> Map.put(:user_id, current_user.id)
        |> Map.put(:subject_id, subject_id)
      else
        # For unauthenticated sessions, explicitly set user_id to nil
        session_attrs
        |> Map.put(:user_id, nil)
        |> Map.put(:subject_id, "pending_authentication")
      end

    case SAML.create_session(session_attrs) do
      {:ok, saml_session} ->
        if current_user do
          {:ok, :show_consent, saml_session, service_provider}
        else
          {:ok, :redirect_to_login, saml_session}
        end

      {:error, changeset} ->
        {:error, "Failed to create SAML session: #{inspect(changeset.errors)}"}
    end
  end

  defp generate_and_send_response(_conn, saml_session, user) do
    service_provider = saml_session.service_provider
    # Preload groups for SAML attribute generation
    user = Authify.Repo.preload(user, :groups)

    case SAML.generate_saml_response(saml_session, service_provider, user) do
      {:ok, saml_response} ->
        # Encode the SAML response
        encoded_response = Base.encode64(saml_response)

        # HTML-escape values to prevent XSS
        acs_url = html_escape_to_string(service_provider.acs_url)

        relay_state_html =
          if saml_session.relay_state do
            escaped_relay = html_escape_to_string(saml_session.relay_state)
            "<input type=\"hidden\" name=\"RelayState\" value=\"#{escaped_relay}\" />"
          else
            ""
          end

        # Generate an HTML form that will auto-submit to the SP's ACS URL
        form_html = """
        <!DOCTYPE html>
        <html>
        <head>
          <title>SAML Response</title>
        </head>
        <body onload="document.forms[0].submit()">
          <form method="post" action="#{acs_url}">
            <input type="hidden" name="SAMLResponse" value="#{encoded_response}" />
            #{relay_state_html}
            <input type="submit" value="Continue" />
          </form>
        </body>
        </html>
        """

        {:ok, form_html}

      {:error, reason} ->
        {:error, "Failed to generate SAML response: #{reason}"}
    end
  end

  defp render_saml_consent(conn, saml_session, _service_provider) do
    # For now, just auto-approve. In a real implementation,
    # you'd show a consent screen similar to OAuth
    organization = conn.assigns.current_organization
    redirect(conn, to: "/#{organization.slug}/saml/continue/#{saml_session.session_id}")
  end

  defp render_saml_error(conn, error) do
    conn
    |> put_status(:bad_request)
    |> text(error)
  end

  # SAML Single Logout (SLO) handler functions

  defp handle_slo_request(conn, saml_request, params) do
    relay_state = params["RelayState"]
    organization = conn.assigns.current_organization

    with {:ok, logout_request} <- parse_saml_logout_request(saml_request),
         {:ok, sp} <- find_service_provider(logout_request.issuer, organization),
         :ok <- terminate_user_sessions_if_present(conn),
         :ok <- log_slo_event_if_user_present(conn, organization, sp),
         {:ok, saml_response} <- SAML.generate_saml_logout_response(logout_request, sp) do
      encoded_response = Base.encode64(saml_response)
      send_saml_logout_response(conn, sp, encoded_response, relay_state)
    else
      {:error, :service_provider_not_found, issuer} ->
        render_saml_error(conn, "Unknown service provider: #{issuer}")

      {:error, :invalid_logout_request, reason} ->
        render_saml_error(conn, "Invalid logout request: #{reason}")

      {:error, reason} ->
        render_saml_error(conn, "Failed to generate logout response: #{reason}")
    end
  end

  defp parse_saml_logout_request(saml_request) do
    case SAML.parse_saml_logout_request(saml_request) do
      {:ok, logout_request} -> {:ok, logout_request}
      {:error, reason} -> {:error, :invalid_logout_request, reason}
    end
  end

  defp find_service_provider(issuer, organization) do
    case SAML.get_service_provider_by_entity_id(issuer, organization) do
      %SAML.ServiceProvider{} = sp -> {:ok, sp}
      nil -> {:error, :service_provider_not_found, issuer}
    end
  end

  defp terminate_user_sessions_if_present(conn) do
    case Authify.Guardian.Plug.current_resource(conn) do
      nil -> :ok
      current_user -> SAML.terminate_all_sessions_for_user(current_user)
    end

    :ok
  end

  defp log_slo_event_if_user_present(conn, organization, sp) do
    case Authify.Guardian.Plug.current_resource(conn) do
      nil ->
        :ok

      current_user ->
        AuditLog.log_event_async(:saml_slo_completed, %{
          organization_id: organization.id,
          actor_type: "user",
          actor_id: current_user.id,
          actor_name: "#{current_user.first_name} #{current_user.last_name}",
          outcome: "success",
          ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
          user_agent: Plug.Conn.get_req_header(conn, "user-agent") |> List.first(),
          metadata: %{
            service_provider_id: sp.id,
            service_provider_name: sp.name,
            entity_id: sp.entity_id,
            initiator: "service_provider"
          }
        })

        :ok
    end
  end

  defp handle_slo_response(conn, _params) do
    # This handles responses to IdP-initiated logout requests
    # For now, just redirect to local logout completion
    redirect(conn, to: "/logout?slo_complete=true")
  end

  defp handle_local_logout(conn) do
    # Direct logout without SAML - perform IdP-initiated logout to all SPs
    current_user = Authify.Guardian.Plug.current_resource(conn)

    if current_user do
      # Find all active SAML sessions for this user
      sessions = SAML.get_active_sessions_for_user(current_user)

      # If no active sessions, redirect to logout
      if Enum.empty?(sessions) do
        redirect(conn, to: "/logout")
      else
        # For each session, try to send logout request to SP
        sp_logout_info =
          sessions
          |> Enum.map(fn session ->
            sp = session.service_provider

            # Try to generate logout request for this SP
            case SAML.generate_saml_logout_request(session, sp) do
              {:ok, saml_request, _request_id} ->
                encoded_request = Base.encode64(saml_request)

                logout_url =
                  "#{sp.sls_url || sp.acs_url}?SAMLRequest=#{URI.encode(encoded_request)}"

                %{name: sp.name, url: logout_url, success: true}

              {:error, _reason} ->
                %{name: sp.name, url: nil, success: false}
            end
          end)

        # For now, just show the logout URLs (in production, you'd handle this more elegantly)
        logout_html = """
        <!DOCTYPE html>
        <html>
        <head>
          <title>Logging out...</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .logout-item { margin: 10px 0; padding: 10px; border: 1px solid #ddd; }
            .success { background-color: #e8f5e8; }
            .error { background-color: #ffeaea; }
          </style>
        </head>
        <body>
          <h2>Single Logout in Progress</h2>
          <p>Logging you out from connected applications:</p>
          #{Enum.map_join(sp_logout_info, "", fn info -> if info.success do
            """
            <div class="logout-item success">
              <strong>#{info.name}</strong>:
              <a href="#{info.url}" target="_blank">Complete logout</a>
            </div>
            """
          else
            """
            <div class="logout-item error">
              <strong>#{info.name}</strong>: Logout failed
            </div>
            """
          end end)}
          <p><a href="/logout">Complete logout from Authify</a></p>
        </body>
        </html>
        """

        conn
        |> put_resp_content_type("text/html")
        |> send_resp(200, logout_html)
      end
    else
      # Not authenticated, redirect to login page
      redirect(conn, to: "/login")
    end
  end

  defp send_saml_logout_response(conn, sp, encoded_response, relay_state) do
    # Send SAML logout response back to service provider
    destination_url = sp.sls_url || sp.acs_url

    # HTML-escape values to prevent XSS
    escaped_destination = html_escape_to_string(destination_url)

    relay_state_html =
      if relay_state do
        escaped_relay = html_escape_to_string(relay_state)
        "<input type=\"hidden\" name=\"RelayState\" value=\"#{escaped_relay}\" />"
      else
        ""
      end

    form_html = """
    <!DOCTYPE html>
    <html>
    <head>
      <title>SAML Logout Response</title>
    </head>
    <body onload="document.forms[0].submit()">
      <form method="post" action="#{escaped_destination}">
        <input type="hidden" name="SAMLResponse" value="#{encoded_response}" />
        #{relay_state_html}
        <input type="submit" value="Complete Logout" />
      </form>
    </body>
    </html>
    """

    conn
    |> put_resp_content_type("text/html")
    |> send_resp(200, form_html)
  end
end
