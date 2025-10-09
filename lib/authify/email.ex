defmodule Authify.Email do
  @moduledoc """
  Email templates and delivery functions for Authify.

  Provides pre-built email templates for common workflows like
  invitations, password resets, and email verification.
  """

  import Swoosh.Email
  alias Authify.Mailer

  @doc """
  Builds an invitation email.

  ## Parameters
    - invitation: The invitation struct with preloaded organization and invited_by
    - accept_url: The full URL for accepting the invitation

  ## Returns
    A Swoosh.Email struct ready to be delivered
  """
  def invitation_email(invitation, accept_url) do
    organization = invitation.organization
    invited_by = invitation.invited_by

    # Get from address from organization settings, or use dev default
    {from_name, from_email} = get_from_address_or_default(organization)

    new()
    |> to(invitation.email)
    |> from({from_name, from_email})
    |> subject("You've been invited to join #{organization.name} on Authify")
    |> html_body(invitation_html_body(invitation, invited_by, organization, accept_url))
    |> text_body(invitation_text_body(invitation, invited_by, organization, accept_url))
  end

  defp invitation_html_body(invitation, invited_by, organization, accept_url) do
    """
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
          line-height: 1.6;
          color: #333;
          max-width: 600px;
          margin: 0 auto;
          padding: 20px;
        }
        .header {
          text-align: center;
          padding: 20px 0;
          border-bottom: 2px solid #0d6efd;
        }
        .logo {
          width: 64px;
          height: 64px;
        }
        .content {
          padding: 30px 0;
        }
        .button {
          display: inline-block;
          padding: 12px 24px;
          background-color: #0d6efd;
          color: #ffffff;
          text-decoration: none;
          border-radius: 5px;
          margin: 20px 0;
        }
        .footer {
          margin-top: 40px;
          padding-top: 20px;
          border-top: 1px solid #dee2e6;
          font-size: 14px;
          color: #6c757d;
        }
        .expiry-notice {
          background-color: #fff3cd;
          border-left: 4px solid #ffc107;
          padding: 12px;
          margin: 20px 0;
        }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>Authify</h1>
      </div>

      <div class="content">
        <h2>You've been invited to join #{organization.name}</h2>

        <p>Hello,</p>

        <p>
          <strong>#{invited_by.first_name} #{invited_by.last_name}</strong> (#{invited_by.email})
          has invited you to join <strong>#{organization.name}</strong> on Authify as a
          <strong>#{String.capitalize(invitation.role)}</strong>.
        </p>

        <p>Click the button below to accept the invitation and create your account:</p>

        <p style="text-align: center;">
          <a href="#{accept_url}" class="button">Accept Invitation</a>
        </p>

        <p style="font-size: 14px; color: #6c757d;">
          Or copy and paste this link into your browser:<br>
          <a href="#{accept_url}">#{accept_url}</a>
        </p>

        <div class="expiry-notice">
          <strong>⏰ This invitation expires on #{format_datetime(invitation.expires_at)}</strong>
        </div>

        <p>
          If you weren't expecting this invitation, you can safely ignore this email.
        </p>
      </div>

      <div class="footer">
        <p>
          This email was sent by #{organization.name} via Authify.<br>
          Questions? Contact <a href="mailto:#{invited_by.email}">#{invited_by.email}</a>
        </p>
      </div>
    </body>
    </html>
    """
  end

  defp invitation_text_body(invitation, invited_by, organization, accept_url) do
    """
    You've been invited to join #{organization.name}

    Hello,

    #{invited_by.first_name} #{invited_by.last_name} (#{invited_by.email}) has invited you to join #{organization.name} on Authify as a #{String.capitalize(invitation.role)}.

    To accept the invitation and create your account, visit:
    #{accept_url}

    This invitation expires on #{format_datetime(invitation.expires_at)}

    If you weren't expecting this invitation, you can safely ignore this email.

    ---
    This email was sent by #{organization.name} via Authify.
    Questions? Contact #{invited_by.email}
    """
  end

  @doc """
  Sends an invitation email.

  Uses Swoosh's deliver/2 which is non-blocking in Elixir thanks to
  connection pooling and the BEAM's concurrency model.

  In development, emails are sent to the local mailbox even without SMTP config.
  In production, SMTP configuration is required.

  ## Parameters
    - invitation: The invitation struct (must have organization and invited_by preloaded)
    - accept_url: The full URL for accepting the invitation

  ## Returns
    - {:ok, metadata} on success
    - {:error, reason} on failure
  """
  def send_invitation_email(invitation, accept_url) do
    organization = invitation.organization

    # In development, send to local mailbox even without SMTP
    if dev_mode?() do
      invitation
      |> invitation_email(accept_url)
      |> Mailer.deliver()
    else
      # In production, require SMTP configuration
      if Mailer.smtp_configured?(organization) do
        # Get SMTP config and build mailer with org-specific settings
        smtp_config = Mailer.get_smtp_config(organization)

        invitation
        |> invitation_email(accept_url)
        |> put_provider_option(:adapter_config, smtp_config)
        |> Mailer.deliver()
      else
        {:error, :smtp_not_configured}
      end
    end
  end

  @doc """
  Builds a password reset email.

  ## Parameters
    - user: The user struct with preloaded organization
    - reset_url: The full URL for resetting the password

  ## Returns
    A Swoosh.Email struct ready to be delivered
  """
  def password_reset_email(user, reset_url) do
    organization = user.organization

    # Get from address from organization settings, or use dev default
    {from_name, from_email} = get_from_address_or_default(organization)

    new()
    |> to(user.email)
    |> from({from_name, from_email})
    |> subject("Password Reset Request - #{organization.name}")
    |> html_body(password_reset_html_body(user, organization, reset_url))
    |> text_body(password_reset_text_body(user, organization, reset_url))
  end

  defp password_reset_html_body(user, organization, reset_url) do
    """
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
          line-height: 1.6;
          color: #333;
          max-width: 600px;
          margin: 0 auto;
          padding: 20px;
        }
        .header {
          text-align: center;
          padding: 20px 0;
          border-bottom: 2px solid #0d6efd;
        }
        .content {
          padding: 30px 0;
        }
        .button {
          display: inline-block;
          padding: 12px 24px;
          background-color: #0d6efd;
          color: #ffffff;
          text-decoration: none;
          border-radius: 5px;
          margin: 20px 0;
        }
        .footer {
          margin-top: 40px;
          padding-top: 20px;
          border-top: 1px solid #dee2e6;
          font-size: 14px;
          color: #6c757d;
        }
        .security-notice {
          background-color: #fff3cd;
          border-left: 4px solid #ffc107;
          padding: 12px;
          margin: 20px 0;
        }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>Authify</h1>
      </div>

      <div class="content">
        <h2>Password Reset Request</h2>

        <p>Hello #{user.first_name},</p>

        <p>
          We received a request to reset your password for your account at
          <strong>#{organization.name}</strong>.
        </p>

        <p>Click the button below to reset your password:</p>

        <p style="text-align: center;">
          <a href="#{reset_url}" class="button">Reset Password</a>
        </p>

        <p style="font-size: 14px; color: #6c757d;">
          Or copy and paste this link into your browser:<br>
          <a href="#{reset_url}">#{reset_url}</a>
        </p>

        <div class="security-notice">
          <strong>⏰ This link expires in 24 hours</strong>
        </div>

        <div class="security-notice">
          <strong>🔒 Security Notice:</strong> If you didn't request this password reset,
          please ignore this email. Your password will not be changed.
        </div>
      </div>

      <div class="footer">
        <p>
          This email was sent by #{organization.name} via Authify.<br>
          If you have questions, please contact your organization administrator.
        </p>
      </div>
    </body>
    </html>
    """
  end

  defp password_reset_text_body(user, organization, reset_url) do
    """
    Password Reset Request

    Hello #{user.first_name},

    We received a request to reset your password for your account at #{organization.name}.

    To reset your password, visit:
    #{reset_url}

    This link expires in 24 hours.

    SECURITY NOTICE: If you didn't request this password reset, please ignore this email.
    Your password will not be changed.

    ---
    This email was sent by #{organization.name} via Authify.
    If you have questions, please contact your organization administrator.
    """
  end

  @doc """
  Sends a password reset email.

  Uses Swoosh's deliver/2 which is non-blocking in Elixir.

  In development, emails are sent to the local mailbox even without SMTP config.
  In production, SMTP configuration is required.

  ## Parameters
    - user: The user struct (must have organization preloaded)
    - reset_url: The full URL for resetting the password

  ## Returns
    - {:ok, metadata} on success
    - {:error, reason} on failure
  """
  def send_password_reset_email(user, reset_url) do
    organization = user.organization

    # In development, send to local mailbox even without SMTP
    if dev_mode?() do
      user
      |> password_reset_email(reset_url)
      |> Mailer.deliver()
    else
      # In production, require SMTP configuration
      if Mailer.smtp_configured?(organization) do
        # Get SMTP config and build mailer with org-specific settings
        smtp_config = Mailer.get_smtp_config(organization)

        user
        |> password_reset_email(reset_url)
        |> put_provider_option(:adapter_config, smtp_config)
        |> Mailer.deliver()
      else
        {:error, :smtp_not_configured}
      end
    end
  end

  @doc """
  Builds an email verification email.

  ## Parameters
    - user: The user struct with preloaded organization
    - verification_url: The full URL for verifying the email

  ## Returns
    A Swoosh.Email struct ready to be delivered
  """
  def email_verification_email(user, verification_url) do
    organization = user.organization

    # Get from address from organization settings, or use dev default
    {from_name, from_email} = get_from_address_or_default(organization)

    new()
    |> to(user.email)
    |> from({from_name, from_email})
    |> subject("Please verify your email - #{organization.name}")
    |> html_body(email_verification_html_body(user, organization, verification_url))
    |> text_body(email_verification_text_body(user, organization, verification_url))
  end

  defp email_verification_html_body(user, organization, verification_url) do
    """
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
          line-height: 1.6;
          color: #333;
          max-width: 600px;
          margin: 0 auto;
          padding: 20px;
        }
        .header {
          text-align: center;
          padding: 20px 0;
          border-bottom: 2px solid #0d6efd;
        }
        .content {
          padding: 30px 0;
        }
        .button {
          display: inline-block;
          padding: 12px 24px;
          background-color: #0d6efd;
          color: #ffffff;
          text-decoration: none;
          border-radius: 5px;
          margin: 20px 0;
        }
        .footer {
          margin-top: 40px;
          padding-top: 20px;
          border-top: 1px solid #dee2e6;
          font-size: 14px;
          color: #6c757d;
        }
        .expiry-notice {
          background-color: #fff3cd;
          border-left: 4px solid #ffc107;
          padding: 12px;
          margin: 20px 0;
        }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>Authify</h1>
      </div>

      <div class="content">
        <h2>Verify Your Email Address</h2>

        <p>Hello #{user.first_name},</p>

        <p>
          Welcome to <strong>#{organization.name}</strong>! Please verify your email address
          to activate your account.
        </p>

        <p>Click the button below to verify your email:</p>

        <p style="text-align: center;">
          <a href="#{verification_url}" class="button">Verify Email</a>
        </p>

        <p style="font-size: 14px; color: #6c757d;">
          Or copy and paste this link into your browser:<br>
          <a href="#{verification_url}">#{verification_url}</a>
        </p>

        <div class="expiry-notice">
          <strong>⏰ This verification link expires in 24 hours</strong>
        </div>

        <p>
          If you didn't create an account, you can safely ignore this email.
        </p>
      </div>

      <div class="footer">
        <p>
          This email was sent by #{organization.name} via Authify.<br>
          If you have questions, please contact your organization administrator.
        </p>
      </div>
    </body>
    </html>
    """
  end

  defp email_verification_text_body(user, organization, verification_url) do
    """
    Verify Your Email Address

    Hello #{user.first_name},

    Welcome to #{organization.name}! Please verify your email address to activate your account.

    To verify your email, visit:
    #{verification_url}

    This verification link expires in 24 hours.

    If you didn't create an account, you can safely ignore this email.

    ---
    This email was sent by #{organization.name} via Authify.
    If you have questions, please contact your organization administrator.
    """
  end

  @doc """
  Sends an email verification email.

  Uses Swoosh's deliver/2 which is non-blocking in Elixir.

  In development, emails are sent to the local mailbox even without SMTP config.
  In production, SMTP configuration is required.

  ## Parameters
    - user: The user struct (must have organization preloaded)
    - verification_url: The full URL for verifying the email

  ## Returns
    - {:ok, metadata} on success
    - {:error, reason} on failure
  """
  def send_email_verification_email(user, verification_url) do
    organization = user.organization

    # In development, send to local mailbox even without SMTP
    if dev_mode?() do
      user
      |> email_verification_email(verification_url)
      |> Mailer.deliver()
    else
      # In production, require SMTP configuration
      if Mailer.smtp_configured?(organization) do
        # Get SMTP config and build mailer with org-specific settings
        smtp_config = Mailer.get_smtp_config(organization)

        user
        |> email_verification_email(verification_url)
        |> put_provider_option(:adapter_config, smtp_config)
        |> Mailer.deliver()
      else
        {:error, :smtp_not_configured}
      end
    end
  end

  # Check if running in development mode
  defp dev_mode? do
    Application.get_env(:authify, :env) == :dev ||
      Mix.env() == :dev
  end

  # Get from address from organization settings, or use dev default
  defp get_from_address_or_default(organization) do
    case Mailer.get_from_address(organization) do
      {_name, _email} = address ->
        address

      nil ->
        # In development, use a default from address
        if dev_mode?() do
          {"Authify (Dev)", "noreply@authify.local"}
        else
          # In production, this should not happen (checked earlier)
          raise "SMTP from address not configured for organization #{organization.slug}"
        end
    end
  end

  # Helper to format datetime for display
  defp format_datetime(nil), do: "N/A"

  defp format_datetime(datetime) do
    datetime
    |> DateTime.to_date()
    |> Date.to_string()
  end
end
