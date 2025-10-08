defmodule Authify.Mailer do
  @moduledoc """
  Mailer module for sending emails.

  Provides functions to get organization-specific SMTP configuration
  and build mailer configurations for use with Swoosh.
  """

  use Swoosh.Mailer, otp_app: :authify

  alias Authify.Configurations

  @doc """
  Gets SMTP configuration for an organization.

  Returns a keyword list suitable for configuring Swoosh SMTP adapter,
  or nil if SMTP is not configured for the organization.

  ## Examples

      iex> get_smtp_config(organization)
      [
        relay: "smtp.gmail.com",
        port: 587,
        username: "test@example.com",
        password: "secret",
        ssl: true,
        tls: :always,
        auth: :always
      ]

      iex> get_smtp_config(unconfigured_org)
      nil
  """
  def get_smtp_config(organization) when is_map(organization) do
    server = Configurations.get_organization_setting(organization, :smtp_server)
    port = Configurations.get_organization_setting(organization, :smtp_port)
    username = Configurations.get_organization_setting(organization, :smtp_username)
    password = Configurations.get_organization_setting(organization, :smtp_password)
    use_ssl = Configurations.get_organization_setting(organization, :smtp_use_ssl)

    # Only return config if server is configured
    if server && server != "" do
      [
        relay: server,
        port: port || 587,
        username: username,
        password: password,
        ssl: use_ssl != false,
        tls: :always,
        auth: :always
      ]
    else
      nil
    end
  end

  @doc """
  Gets the 'from' address for emails sent by an organization.

  Returns a tuple of {name, email} or nil if not configured.

  ## Examples

      iex> get_from_address(organization)
      {"Acme Corp", "noreply@example.com"}

      iex> get_from_address(unconfigured_org)
      nil
  """
  def get_from_address(organization) when is_map(organization) do
    email = Configurations.get_organization_setting(organization, :smtp_from_email)
    name = Configurations.get_organization_setting(organization, :smtp_from_name)

    if email && email != "" do
      {name || organization.name, email}
    else
      nil
    end
  end

  @doc """
  Checks if SMTP is configured for an organization.

  Returns true if the organization has a valid SMTP configuration.

  ## Examples

      iex> smtp_configured?(organization)
      true

      iex> smtp_configured?(unconfigured_org)
      false
  """
  def smtp_configured?(organization) when is_map(organization) do
    get_smtp_config(organization) != nil && get_from_address(organization) != nil
  end
end
