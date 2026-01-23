defmodule AuthifyWeb.WebAuthnController do
  @moduledoc """
  Controller for WebAuthn credential registration and management.

  Handles:
  - Credential registration (setup, register_begin, register_complete)
  - Credential management (index, rename, revoke, revoke_all)
  """

  use AuthifyWeb, :controller

  alias Authify.{Accounts, Repo}
  alias Authify.Accounts.User
  alias Authify.MFA.WebAuthn

  # ============================================================================
  # Registration Flow
  # ============================================================================

  @doc """
  Display WebAuthn credential registration page.
  """
  def setup(conn, _params) do
    current_user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    # Get existing credentials count
    credentials = WebAuthn.list_credentials(current_user)

    render(conn, :setup,
      user: current_user,
      organization: organization,
      credentials_count: length(credentials)
    )
  end

  @doc """
  Begin WebAuthn registration by generating a challenge.
  Returns JSON with registration options for the client.
  """
  def register_begin(conn, params) do
    current_user = conn.assigns.current_user

    # Extract options from params
    opts = [
      authenticator_attachment: params["authenticatorAttachment"],
      user_verification: params["userVerification"] || "preferred",
      attestation: params["attestation"] || "none",
      credential_type: params["credentialType"],
      ip_address: get_client_ip(conn),
      user_agent: get_req_header(conn, "user-agent") |> List.first()
    ]

    case WebAuthn.begin_registration(current_user, opts) do
      {:ok, %{challenge: challenge, options: options}} ->
        # Store challenge in session for verification
        conn
        |> put_session(:webauthn_registration_challenge, challenge)
        |> json(%{success: true, options: options})

      {:error, _changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{success: false, error: "Failed to generate challenge"})
    end
  end

  @doc """
  Complete WebAuthn registration by verifying the attestation response.
  """
  def register_complete(conn, params) do
    current_user = conn.assigns.current_user

    # Get challenge from session
    challenge = get_session(conn, :webauthn_registration_challenge)

    if challenge do
      # Extract attestation response and credential name
      attestation_response = params["attestationResponse"]
      credential_name = params["credentialName"]
      credential_type = params["credentialType"]

      opts = [
        name: credential_name,
        credential_type: credential_type,
        ip_address: get_client_ip(conn)
      ]

      case WebAuthn.complete_registration(current_user, attestation_response, challenge, opts) do
        {:ok, credential} ->
          # Clear challenge from session
          conn = delete_session(conn, :webauthn_registration_challenge)

          json(conn, %{
            success: true,
            message: "Security key registered successfully",
            credential: %{
              id: credential.id,
              name: credential.name,
              type: credential.credential_type
            }
          })

        {:error, reason} ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{
            success: false,
            error: format_error(reason)
          })
      end
    else
      conn
      |> put_status(:bad_request)
      |> json(%{success: false, error: "No active registration challenge"})
    end
  end

  # ============================================================================
  # Credential Management
  # ============================================================================

  @doc """
  List all WebAuthn credentials for the current user.
  """
  def index(conn, _params) do
    current_user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    credentials = WebAuthn.list_credentials(current_user)

    render(conn, :index,
      user: current_user,
      organization: organization,
      credentials: credentials
    )
  end

  @doc """
  Update the friendly name of a credential.
  """
  def rename(conn, %{"id" => id, "name" => name}) do
    current_user = conn.assigns.current_user

    case WebAuthn.get_credential(id) do
      {:ok, credential} ->
        # Verify ownership
        if credential.user_id == current_user.id do
          case WebAuthn.update_credential_name(id, name) do
            {:ok, _updated_credential} ->
              json(conn, %{success: true, credential: %{id: id, name: name}})

            {:error, _changeset} ->
              conn
              |> put_status(:unprocessable_entity)
              |> json(%{success: false, error: "Failed to update credential name"})
          end
        else
          conn
          |> put_status(:forbidden)
          |> json(%{success: false, error: "Not authorized"})
        end

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{success: false, error: "Credential not found"})
    end
  end

  @doc """
  Revoke (delete) a specific credential.
  """
  def revoke(conn, %{"id" => id}) do
    current_user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    case WebAuthn.get_credential(id) do
      {:ok, credential} ->
        # Verify ownership
        if credential.user_id == current_user.id do
          case WebAuthn.revoke_credential(id) do
            {:ok, _deleted_credential} ->
              conn
              |> put_flash(:info, "Security key revoked successfully.")
              |> redirect(to: ~p"/#{organization.slug}/profile/mfa")

            {:error, _changeset} ->
              conn
              |> put_flash(:error, "Failed to revoke security key.")
              |> redirect(to: ~p"/#{organization.slug}/profile/mfa")
          end
        else
          conn
          |> put_flash(:error, "Not authorized.")
          |> redirect(to: ~p"/#{organization.slug}/profile/mfa")
        end

      {:error, :not_found} ->
        conn
        |> put_flash(:error, "Credential not found.")
        |> redirect(to: ~p"/#{organization.slug}/profile/mfa")
    end
  end

  @doc """
  Revoke all credentials for the current user.
  Requires password re-authentication.
  """
  def revoke_all(conn, %{"password" => password}) do
    current_user = conn.assigns.current_user
    current_user_with_emails = Repo.preload(current_user, :emails)
    organization = conn.assigns.current_organization

    # Verify password
    case Accounts.authenticate_user(
           User.get_primary_email_value(current_user_with_emails),
           password,
           organization.id
         ) do
      {:ok, _user} ->
        case WebAuthn.revoke_all_credentials(current_user) do
          {:ok, _count} ->
            conn
            |> put_flash(:info, "All security keys have been revoked.")
            |> redirect(to: ~p"/#{organization.slug}/profile/mfa")
        end

      {:error, _} ->
        conn
        |> put_flash(:error, "Invalid password.")
        |> redirect(to: ~p"/#{organization.slug}/profile/mfa")
    end
  end

  def revoke_all(conn, _params) do
    organization = conn.assigns.current_organization

    conn
    |> put_flash(:error, "Password is required to revoke all security keys.")
    |> redirect(to: ~p"/#{organization.slug}/profile/mfa")
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp get_client_ip(conn) do
    case Plug.Conn.get_req_header(conn, "x-forwarded-for") do
      [ip | _] -> ip
      _ -> to_string(:inet_parse.ntoa(conn.remote_ip))
    end
  end

  defp format_error(:invalid_challenge), do: "Invalid or expired challenge"
  defp format_error(:challenge_already_used), do: "Challenge has already been used"
  defp format_error(:challenge_expired), do: "Challenge has expired"
  defp format_error(:challenge_mismatch), do: "Challenge verification failed"
  defp format_error(:invalid_attestation_object), do: "Invalid attestation data"
  defp format_error(:no_credential_data), do: "No credential data in attestation"
  defp format_error(_), do: "Registration failed"
end
