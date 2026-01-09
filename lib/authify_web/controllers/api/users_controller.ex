defmodule AuthifyWeb.API.UsersController do
  use AuthifyWeb.API.BaseController

  alias Authify.Accounts
  alias AuthifyWeb.Helpers.AuditHelper

  @doc """
  GET /{org_slug}/api/users

  List users in the current organization with pagination.
  Requires users:read scope.
  """
  def index(conn, params) do
    case ensure_scope(conn, "users:read") do
      :ok ->
        organization = conn.assigns.current_organization
        page = String.to_integer(params["page"] || "1")
        per_page = min(String.to_integer(params["per_page"] || "25"), 100)

        users = Accounts.list_users(organization.id, page: page, per_page: per_page)
        total_count = Accounts.count_users(organization.id)

        render_collection_response(conn, users,
          resource_type: "user",
          exclude: [:password_hash, :email_verified_at, :password_reset_token],
          page_info: %{
            page: page,
            per_page: per_page,
            total: total_count
          }
        )

      {:error, response} ->
        response
    end
  end

  @doc """
  GET /{org_slug}/api/users/:id

  Get a specific user by ID.
  Requires users:read scope.
  """
  def show(conn, %{"id" => id}) do
    case ensure_scope(conn, "users:read") do
      :ok ->
        organization = conn.assigns.current_organization

        case Accounts.get_user_in_organization(id, organization.id) do
          nil ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "User not found in organization"
            )

          user ->
            render_api_response(conn, user,
              resource_type: "user",
              exclude: [:password_hash, :email_verified_at, :password_reset_token]
            )
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  POST /{org_slug}/api/users

  Create a new user in the current organization.
  Requires users:write scope.
  """
  def create(conn, %{"user" => user_params}) do
    case ensure_scope(conn, "users:write") do
      :ok ->
        organization = conn.assigns.current_organization
        user_params_with_org = Map.put(user_params, "organization_id", organization.id)

        case Accounts.create_user(user_params_with_org) do
          {:ok, user} ->
            AuditHelper.log_user_created(conn, user, extra_metadata: %{"source" => "api"})

            render_api_response(conn, user,
              resource_type: "user",
              exclude: [:password_hash, :email_verified_at, :password_reset_token],
              status: :created
            )

          {:error, %Ecto.Changeset{} = changeset} ->
            render_validation_errors(conn, changeset)
        end

      {:error, response} ->
        response
    end
  end

  def create(conn, _params) do
    case ensure_scope(conn, "users:write") do
      :ok ->
        render_error_response(
          conn,
          :bad_request,
          "invalid_request",
          "Request must include user parameters"
        )

      {:error, response} ->
        response
    end
  end

  @doc """
  PUT /{org_slug}/api/users/:id

  Update a user's profile information.
  Requires users:write scope.
  """
  def update(conn, %{"id" => id, "user" => user_params}) do
    case ensure_scope(conn, "users:write") do
      :ok ->
        organization = conn.assigns.current_organization

        case Accounts.get_user_in_organization(id, organization.id) do
          nil ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "User not found in organization"
            )

          user ->
            case Accounts.update_user(user, user_params) do
              {:ok, updated_user} ->
                AuditHelper.log_user_profile_update(conn, user, updated_user,
                  extra_metadata: %{"source" => "api", "admin_update" => true}
                )

                render_api_response(conn, updated_user,
                  resource_type: "user",
                  exclude: [:password_hash, :email_verified_at, :password_reset_token]
                )

              {:error, %Ecto.Changeset{} = changeset} ->
                AuditHelper.log_user_profile_failure(conn, user, changeset,
                  extra_metadata: %{"source" => "api", "admin_update" => true}
                )

                render_validation_errors(conn, changeset)
            end
        end

      {:error, response} ->
        response
    end
  end

  def update(conn, %{"id" => _id}) do
    case ensure_scope(conn, "users:write") do
      :ok ->
        render_error_response(
          conn,
          :bad_request,
          "invalid_request",
          "Request must include user parameters"
        )

      {:error, response} ->
        response
    end
  end

  @doc """
  DELETE /{org_slug}/api/users/:id

  Delete a user from the organization.
  Requires users:write scope.
  """
  def delete(conn, %{"id" => id}) do
    case ensure_scope(conn, "users:write") do
      :ok ->
        organization = conn.assigns.current_organization
        current_user = conn.assigns.current_user

        case Accounts.get_user_in_organization(id, organization.id) do
          nil ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "User not found in organization"
            )

          user ->
            # Prevent self-deletion
            if user.id == current_user.id do
              render_error_response(
                conn,
                :forbidden,
                "invalid_operation",
                "You cannot delete your own account"
              )
            else
              case Accounts.delete_user(user) do
                {:ok, deleted_user} ->
                  AuditHelper.log_user_deleted(conn, deleted_user,
                    extra_metadata: %{"source" => "api"}
                  )

                  conn |> put_status(:no_content) |> json(%{})

                {:error, %Ecto.Changeset{} = changeset} ->
                  render_validation_errors(conn, changeset)
              end
            end
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  PUT /{org_slug}/api/users/:id/role

  Update a user's role in the organization.
  Requires users:write scope.
  """
  def update_role(conn, %{"id" => id, "role" => role}) do
    case ensure_scope(conn, "users:write") do
      :ok ->
        organization = conn.assigns.current_organization

        case Accounts.get_user_in_organization(id, organization.id) do
          nil ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "User not found in organization"
            )

          user ->
            if role in ["user", "admin"] do
              old_role = user.role

              case Accounts.update_user_role(user, role) do
                {:ok, updated_user} ->
                  AuditHelper.log_role_assigned(conn, updated_user, old_role, role,
                    extra_metadata: %{"source" => "api"}
                  )

                  render_api_response(conn, updated_user,
                    resource_type: "user",
                    exclude: [:password_hash, :email_verified_at, :password_reset_token]
                  )

                {:error, changeset} ->
                  render_validation_errors(conn, changeset)
              end
            else
              render_error_response(
                conn,
                :unprocessable_entity,
                "validation_failed",
                "Invalid role specified",
                %{"role" => ["must be either 'user' or 'admin'"]}
              )
            end
        end

      {:error, response} ->
        response
    end
  end

  def update_role(conn, %{"id" => _id}) do
    case ensure_scope(conn, "users:write") do
      :ok ->
        render_error_response(
          conn,
          :bad_request,
          "invalid_request",
          "Request must include role parameter"
        )

      {:error, response} ->
        response
    end
  end

  @doc """
  GET /{org_slug}/api/users/:id/mfa

  Get MFA status for a user.
  Requires users:read scope.
  """
  def mfa_status(conn, %{"id" => id}) do
    case ensure_scope(conn, "users:read") do
      :ok ->
        organization = conn.assigns.current_organization

        case Accounts.get_user_in_organization(id, organization.id) do
          nil ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "User not found in organization"
            )

          user ->
            mfa_data = build_mfa_status(user)

            json(conn, %{
              data: %{
                id: user.id,
                type: "mfa_status",
                attributes: mfa_data
              },
              links: %{
                self: url(~p"/#{organization.slug}/api/users/#{user.id}/mfa")
              }
            })
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  POST /{org_slug}/api/users/:id/mfa/unlock

  Unlock a user who is locked out from MFA.
  Requires users:write scope.
  """
  def mfa_unlock(conn, %{"id" => id}) do
    case ensure_scope(conn, "users:write") do
      :ok ->
        organization = conn.assigns.current_organization
        current_user = conn.assigns.current_user

        case Accounts.get_user_in_organization(id, organization.id) do
          nil ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "User not found in organization"
            )

          user ->
            {:ok, _unlocked_user} = Authify.MFA.unlock_user(user, current_user)

            AuditHelper.log_event_async(
              conn,
              :mfa_unlocked,
              "user",
              user.id,
              "success",
              %{"source" => "api", "target_user_email" => user.email}
            )

            json(conn, %{
              data: %{
                id: user.id,
                type: "mfa_unlock",
                attributes: %{
                  message: "User MFA lockout has been removed"
                }
              },
              links: %{
                self: url(~p"/#{organization.slug}/api/users/#{user.id}/mfa"),
                user: url(~p"/#{organization.slug}/api/users/#{user.id}")
              }
            })
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  POST /{org_slug}/api/users/:id/mfa/reset

  Reset a user's MFA completely (disable TOTP, revoke devices, clear codes).
  Requires users:write scope.
  """
  def mfa_reset(conn, %{"id" => id}) do
    case ensure_scope(conn, "users:write") do
      :ok ->
        organization = conn.assigns.current_organization
        current_user = conn.assigns.current_user

        case Accounts.get_user_in_organization(id, organization.id) do
          nil ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "User not found in organization"
            )

          user ->
            {:ok, _reset_user} = Authify.MFA.admin_reset_totp(user, current_user)

            AuditHelper.log_event_async(
              conn,
              :mfa_reset,
              "user",
              user.id,
              "success",
              %{"source" => "api", "target_user_email" => user.email}
            )

            json(conn, %{
              data: %{
                id: user.id,
                type: "mfa_reset",
                attributes: %{
                  message: "User MFA has been reset. They will need to set it up again."
                }
              },
              links: %{
                self: url(~p"/#{organization.slug}/api/users/#{user.id}/mfa"),
                user: url(~p"/#{organization.slug}/api/users/#{user.id}")
              }
            })
        end

      {:error, response} ->
        response
    end
  end

  # Private helper to build MFA status
  defp build_mfa_status(user) do
    if Accounts.User.totp_enabled?(user) do
      # Count backup codes
      backup_codes_count = Authify.MFA.backup_codes_count(user)

      # Count trusted devices
      trusted_devices_count =
        user
        |> Authify.MFA.list_trusted_devices()
        |> length()

      # Check for active lockout
      lockout_info =
        case Authify.MFA.check_lockout(user) do
          {:ok, :no_lockout} ->
            nil

          {:error, {:locked, locked_until}} ->
            %{
              locked: true,
              locked_until: DateTime.to_iso8601(locked_until)
            }
        end

      %{
        totp_enabled: true,
        totp_enabled_at: DateTime.to_iso8601(user.totp_enabled_at),
        backup_codes_count: backup_codes_count,
        trusted_devices_count: trusted_devices_count,
        lockout: lockout_info
      }
    else
      %{
        totp_enabled: false,
        totp_enabled_at: nil,
        backup_codes_count: 0,
        trusted_devices_count: 0,
        lockout: nil
      }
    end
  end
end
