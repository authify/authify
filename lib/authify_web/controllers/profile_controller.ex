defmodule AuthifyWeb.ProfileController do
  use AuthifyWeb, :controller
  import Phoenix.Component, only: [to_form: 1]

  alias Authify.Accounts
  alias Authify.Accounts.PersonalAccessToken

  def show(conn, _params) do
    current_user = conn.assigns.current_user
    organization = conn.assigns.current_organization

    render(conn, :show,
      user: current_user,
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
      {:ok, _updated_user} ->
        conn
        |> put_flash(:info, "Profile updated successfully.")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/profile")

      {:error, %Ecto.Changeset{} = changeset} ->
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
        {:ok, _updated_user} ->
          conn
          |> put_flash(:info, "Password updated successfully.")
          |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/profile")

        {:error, %Ecto.Changeset{} = changeset} ->
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

      render(conn, :edit_password,
        user: current_user,
        organization: organization,
        changeset: changeset
      )
    end
  end

  def resend_verification(conn, _params) do
    current_user = conn.assigns.current_user |> Authify.Repo.preload(:organization)

    # Check if already verified
    if current_user.email_confirmed_at do
      conn
      |> put_flash(:info, "Your email is already verified.")
      |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/profile")
    else
      # Generate new verification token
      case Accounts.generate_email_verification_token(current_user) do
        {:ok, _updated_user, plaintext_token} ->
          # Build the verification URL
          verification_url =
            Accounts.build_email_verification_url(current_user.organization, plaintext_token)

          # Send verification email
          case Authify.Email.send_email_verification_email(current_user, verification_url) do
            {:ok, _metadata} ->
              require Logger
              Logger.info("Email verification resent to #{current_user.email}")

              conn
              |> put_flash(
                :info,
                "Verification email sent! Please check your inbox and click the verification link."
              )
              |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/profile")

            {:error, reason} ->
              require Logger
              Logger.error("Failed to send verification email: #{inspect(reason)}")

              conn
              |> put_flash(:error, "Unable to send verification email. Please try again later.")
              |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/profile")
          end

        {:error, _changeset} ->
          conn
          |> put_flash(:error, "Unable to generate verification token. Please try again.")
          |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/profile")
      end
    end
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
        conn
        |> put_flash(
          :info,
          "Personal access token created successfully. Make sure to copy it now - you won't be able to see it again!"
        )
        # Special flash for showing the token once
        |> put_flash(:token, pat.token)
        |> redirect(
          to: ~p"/#{conn.assigns.current_organization.slug}/profile/personal-access-tokens"
        )

      {:error, %Ecto.Changeset{} = changeset} ->
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

    pat = Accounts.get_personal_access_token!(id, current_user)

    case Accounts.delete_personal_access_token(pat) do
      {:ok, _pat} ->
        conn
        |> put_flash(:info, "Personal access token deleted successfully.")
        |> redirect(
          to: ~p"/#{conn.assigns.current_organization.slug}/profile/personal-access-tokens"
        )

      {:error, _changeset} ->
        conn
        |> put_flash(:error, "Unable to delete personal access token.")
        |> redirect(
          to: ~p"/#{conn.assigns.current_organization.slug}/profile/personal-access-tokens"
        )
    end
  end
end
