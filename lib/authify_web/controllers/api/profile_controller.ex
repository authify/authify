defmodule AuthifyWeb.API.ProfileController do
  use AuthifyWeb.API.BaseController

  alias Authify.Accounts
  alias AuthifyWeb.Helpers.AuditHelper

  def show(conn, _params) do
    current_user = conn.assigns.current_user

    render_api_response(conn, current_user,
      resource_type: "user",
      exclude: [:password_hash, :email_verified_at, :password_reset_token]
    )
  end

  def update(conn, %{"user" => user_params}) do
    current_user = conn.assigns.current_user

    # Only allow updating certain profile fields
    allowed_params = Map.take(user_params, ["first_name", "last_name"])

    case Accounts.update_user(current_user, allowed_params) do
      {:ok, updated_user} ->
        AuditHelper.log_user_profile_update(conn, current_user, updated_user,
          extra_metadata: %{"source" => "api"}
        )

        render_api_response(conn, updated_user, resource_type: "user")

      {:error, changeset} ->
        AuditHelper.log_user_profile_failure(conn, current_user, changeset,
          extra_metadata: %{"source" => "api"}
        )

        render_validation_errors(conn, changeset)
    end
  end
end
