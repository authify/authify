defmodule AuthifyWeb.ProfileController do
  use AuthifyWeb, :controller
  import Phoenix.Component, only: [to_form: 1]

  alias Authify.Accounts
  alias Authify.Accounts.{PersonalAccessToken, User}
  alias AuthifyWeb.Helpers.AuditHelper

  def show(conn, _params) do
    current_user = conn.assigns.current_user |> Authify.Repo.preload(:emails)
    organization = conn.assigns.current_organization
    primary_email = User.get_primary_email(current_user)

    render(conn, :show,
      user: current_user,
      user_email: primary_email.value,
      user_email_verified: primary_email.verified_at != nil,
      user_email_verified_at: primary_email.verified_at,
      organization: organization
    )
  end

  def edit(conn, _params) do
    current_user = conn.assigns.current_user
    organization = conn.assigns.current_organization
    changeset = Accounts.change_user_form(current_user)

    render(conn, :edit,
      user: current_user,
      organization: organization,
      changeset: changeset
    )
  end

  def update(conn, %{"user" => user_params}) do
    current_user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    case Accounts.update_user_profile(current_user, user_params) do
      {:ok, updated_user} ->
        AuditHelper.log_user_profile_update(conn, current_user, updated_user,
          extra_metadata: %{"source" => "web"}
        )

        conn
        |> put_flash(:info, "Profile updated successfully.")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/profile")

      {:error, %Ecto.Changeset{} = changeset} ->
        AuditHelper.log_user_profile_failure(conn, current_user, changeset,
          extra_metadata: %{"source" => "web"}
        )

        render(conn, :edit,
          user: current_user,
          organization: organization,
          changeset: changeset
        )
    end
  end

  def edit_password(conn, _params) do
    current_user = conn.assigns.current_user
    organization = conn.assigns.current_organization
    changeset = Accounts.change_user_password(current_user)

    render(conn, :edit_password,
      user: current_user,
      organization: organization,
      changeset: changeset
    )
  end

  def update_password(conn, %{"user" => password_params}) do
    current_user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    # Verify current password
    if password_params["current_password"] &&
         Accounts.User.valid_password?(current_user, password_params["current_password"]) do
      case Accounts.update_user_password(current_user, password_params) do
        {:ok, updated_user} ->
          AuditHelper.log_password_change(conn, updated_user,
            extra_metadata: %{"source" => "web", "method" => "self_service"}
          )

          conn
          |> put_flash(:info, "Password updated successfully.")
          |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/profile")

        {:error, %Ecto.Changeset{} = changeset} ->
          AuditHelper.log_password_change_failure(conn, current_user, changeset,
            extra_metadata: %{"source" => "web", "method" => "self_service"}
          )

          render(conn, :edit_password,
            user: current_user,
            organization: organization,
            changeset: changeset
          )
      end
    else
      changeset =
        current_user
        |> Accounts.change_user_password(password_params)
        |> Ecto.Changeset.add_error(:current_password, "is invalid")

      AuditHelper.log_password_change_failure(conn, current_user, changeset,
        extra_metadata: %{"source" => "web", "method" => "self_service"}
      )

      render(conn, :edit_password,
        user: current_user,
        organization: organization,
        changeset: changeset
      )
    end
  end

  def resend_verification(conn, _params) do
    current_user = conn.assigns.current_user |> Authify.Repo.preload([:organization, :emails])
    primary_email = User.get_primary_email(current_user)

    if primary_email.verified_at do
      handle_already_verified(conn, current_user)
    else
      send_verification_email(conn, current_user, primary_email)
    end
  end

  defp handle_already_verified(conn, current_user) do
    AuditHelper.log_email_verification_resend_failure(
      conn,
      current_user,
      "already_verified",
      extra_metadata: %{"source" => "web"}
    )

    conn
    |> put_flash(:info, "Your email is already verified.")
    |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/profile")
  end

  defp send_verification_email(conn, current_user, primary_email) do
    case Accounts.generate_email_verification_token(primary_email) do
      {:ok, updated_email, plaintext_token} ->
        handle_verification_token_generated(conn, current_user, updated_email, plaintext_token)

      {:error, changeset} ->
        handle_token_generation_error(conn, current_user, primary_email, changeset)
    end
  end

  defp handle_verification_token_generated(conn, current_user, updated_email, plaintext_token) do
    verification_url =
      Accounts.build_email_verification_url(current_user.organization, plaintext_token)

    case Authify.Email.send_email_verification_email(current_user, verification_url) do
      {:ok, _metadata} ->
        handle_email_sent_successfully(conn, current_user, updated_email)

      {:error, reason} ->
        handle_email_send_error(conn, current_user, reason)
    end
  end

  defp handle_email_sent_successfully(conn, current_user, updated_email) do
    require Logger

    Logger.info("Email verification resent to #{User.get_primary_email_value(current_user)}")

    AuditHelper.log_email_verification_resent(conn, current_user,
      extra_metadata: %{"source" => "web", "email" => updated_email.value}
    )

    conn
    |> put_flash(
      :info,
      "Verification email sent! Please check your inbox and click the verification link."
    )
    |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/profile")
  end

  defp handle_email_send_error(conn, current_user, reason) do
    require Logger
    Logger.error("Failed to send verification email: #{inspect(reason)}")

    AuditHelper.log_email_verification_resend_failure(
      conn,
      current_user,
      "email_send_failed",
      extra_metadata: %{"source" => "web", "email_error" => inspect(reason)}
    )

    conn
    |> put_flash(:error, "Unable to send verification email. Please try again later.")
    |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/profile")
  end

  defp handle_token_generation_error(conn, current_user, primary_email, changeset) do
    AuditHelper.log_email_verification_resend_failure(
      conn,
      current_user,
      "token_generation_failed",
      errors: changeset,
      extra_metadata: %{
        "source" => "web",
        "email_id" => primary_email.id
      }
    )

    conn
    |> put_flash(:error, "Unable to generate verification token. Please try again.")
    |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/profile")
  end

  # Personal Access Token actions

  def personal_access_tokens(conn, _params) do
    current_user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    personal_access_tokens = Accounts.list_personal_access_tokens(current_user)

    render(conn, :personal_access_tokens,
      user: current_user,
      organization: organization,
      personal_access_tokens: personal_access_tokens,
      form: to_form(Accounts.change_personal_access_token(%PersonalAccessToken{}))
    )
  end

  def create_personal_access_token(conn, %{"personal_access_token" => pat_params}) do
    current_user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    case Accounts.create_personal_access_token(current_user, organization, pat_params) do
      {:ok, pat} ->
        pat = Authify.Repo.preload(pat, :scopes)

        AuditHelper.log_personal_access_token_event(conn, :personal_access_token_created, pat,
          extra_metadata: %{"source" => "web"}
        )

        conn
        |> put_flash(
          :info,
          "Personal access token created successfully. Make sure to copy it now - you won't be able to see it again!"
        )
        # Special flash for showing the token once
        |> put_flash(:token, pat.plaintext_token)
        |> redirect(
          to: ~p"/#{conn.assigns.current_organization.slug}/profile/personal-access-tokens"
        )

      {:error, %Ecto.Changeset{} = changeset} ->
        AuditHelper.log_personal_access_token_failure(
          conn,
          :personal_access_token_created,
          changeset,
          extra_metadata: %{"source" => "web"}
        )

        personal_access_tokens = Accounts.list_personal_access_tokens(current_user)

        render(conn, :personal_access_tokens,
          user: current_user,
          organization: organization,
          personal_access_tokens: personal_access_tokens,
          form: to_form(changeset)
        )
    end
  end

  def delete_personal_access_token(conn, %{"id" => id}) do
    current_user = conn.assigns.current_user
    pat = Accounts.get_personal_access_token!(id, current_user) |> Authify.Repo.preload(:scopes)

    case Accounts.delete_personal_access_token(pat) do
      {:ok, deleted_pat} ->
        AuditHelper.log_personal_access_token_event(
          conn,
          :personal_access_token_deleted,
          deleted_pat,
          extra_metadata: %{"source" => "web"}
        )

        conn
        |> put_flash(:info, "Personal access token deleted successfully.")
        |> redirect(
          to: ~p"/#{conn.assigns.current_organization.slug}/profile/personal-access-tokens"
        )

      {:error, changeset} ->
        AuditHelper.log_personal_access_token_failure(
          conn,
          :personal_access_token_deleted,
          changeset,
          personal_access_token: pat,
          extra_metadata: %{"source" => "web"}
        )

        conn
        |> put_flash(:error, "Unable to delete personal access token.")
        |> redirect(
          to: ~p"/#{conn.assigns.current_organization.slug}/profile/personal-access-tokens"
        )
    end
  end
end
