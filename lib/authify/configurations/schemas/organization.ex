defmodule Authify.Configurations.Schemas.Organization do
  @moduledoc """
  Configuration schema for organization-specific settings.

  These settings control organization-level behavior, features, and profile information.
  """

  @behaviour Authify.Configurations.Schema

  @impl true
  def schema_name, do: "organization"

  @impl true
  def settings do
    [
      # Rate Limit Quotas (Super Admin Only)
      %{
        name: :quota_auth_rate_limit,
        description:
          "Maximum authentication requests per minute per IP for this organization (super admin only)",
        value_type: :integer,
        default_value: 10,
        required: true,
        super_admin_only: true,
        validation_fn: &validate_positive_integer/1
      },
      %{
        name: :quota_oauth_rate_limit,
        description:
          "Maximum OAuth/OIDC requests per minute per IP for this organization (super admin only)",
        value_type: :integer,
        default_value: 60,
        required: true,
        super_admin_only: true,
        validation_fn: &validate_positive_integer/1
      },
      %{
        name: :quota_saml_rate_limit,
        description:
          "Maximum SAML requests per minute per IP for this organization (super admin only)",
        value_type: :integer,
        default_value: 30,
        required: true,
        super_admin_only: true,
        validation_fn: &validate_positive_integer/1
      },
      %{
        name: :quota_api_rate_limit,
        description:
          "Maximum Management API requests per minute per user/IP for this organization (super admin only)",
        value_type: :integer,
        default_value: 100,
        required: true,
        super_admin_only: true,
        validation_fn: &validate_positive_integer/1
      },
      # Rate Limits (Organization Admin Configurable)
      %{
        name: :auth_rate_limit,
        description:
          "Authentication requests per minute per IP. Must be less than or equal to quota. Leave empty to use quota value.",
        value_type: :integer,
        default_value: nil,
        required: false,
        validation_fn: nil
      },
      %{
        name: :oauth_rate_limit,
        description:
          "OAuth/OIDC requests per minute per IP. Must be less than or equal to quota. Leave empty to use quota value.",
        value_type: :integer,
        default_value: nil,
        required: false,
        validation_fn: nil
      },
      %{
        name: :saml_rate_limit,
        description:
          "SAML requests per minute per IP. Must be less than or equal to quota. Leave empty to use quota value.",
        value_type: :integer,
        default_value: nil,
        required: false,
        validation_fn: nil
      },
      %{
        name: :api_rate_limit,
        description:
          "Management API requests per minute per user/IP. Must be less than or equal to quota. Leave empty to use quota value.",
        value_type: :integer,
        default_value: nil,
        required: false,
        validation_fn: nil
      },
      # Feature toggles
      %{
        name: :allow_invitations,
        description: "Allow organization admins to invite new users",
        value_type: :boolean,
        default_value: true,
        required: false,
        validation_fn: nil
      },
      %{
        name: :allow_saml,
        description: "Enable SAML identity provider functionality for this organization",
        value_type: :boolean,
        default_value: true,
        required: false,
        validation_fn: nil
      },
      %{
        name: :allow_oauth,
        description: "Enable OAuth2/OIDC identity provider functionality for this organization",
        value_type: :boolean,
        default_value: true,
        required: false,
        validation_fn: nil
      },
      # Profile/branding fields
      %{
        name: :description,
        description: "Organization description",
        value_type: :string,
        default_value: nil,
        required: false,
        validation_fn: &validate_description/1
      },
      %{
        name: :website_url,
        description: "Organization website URL",
        value_type: :string,
        default_value: nil,
        required: false,
        validation_fn: &validate_url/1
      },
      %{
        name: :contact_email,
        description: "Organization contact email",
        value_type: :string,
        default_value: nil,
        required: false,
        validation_fn: &validate_email/1
      },
      %{
        name: :logo_url,
        description: "Organization logo URL",
        value_type: :string,
        default_value: nil,
        required: false,
        validation_fn: &validate_url/1
      },
      # Domain configuration
      %{
        name: :email_link_domain,
        description:
          "Domain used in email links (invitations, password reset, etc.). Must be either the organization's subdomain or one of its configured CNAMEs.",
        value_type: :string,
        default_value: nil,
        required: false,
        validation_fn: nil
      },
      # SMTP configuration
      %{
        name: :smtp_server,
        description: "SMTP server hostname (e.g., smtp.gmail.com)",
        value_type: :string,
        default_value: nil,
        required: false,
        validation_fn: &validate_smtp_server/1
      },
      %{
        name: :smtp_port,
        description: "SMTP server port (typically 587 for TLS, 465 for SSL, 25 for unencrypted)",
        value_type: :integer,
        default_value: 587,
        required: false,
        validation_fn: &validate_smtp_port/1
      },
      %{
        name: :smtp_username,
        description: "SMTP authentication username",
        value_type: :string,
        default_value: nil,
        required: false,
        validation_fn: nil
      },
      %{
        name: :smtp_password,
        description: "SMTP authentication password",
        value_type: :string,
        default_value: nil,
        required: false,
        validation_fn: nil,
        encrypted: true
      },
      %{
        name: :smtp_from_email,
        description: "Email address to use in the 'From' field",
        value_type: :string,
        default_value: nil,
        required: false,
        validation_fn: &validate_email/1
      },
      %{
        name: :smtp_from_name,
        description: "Name to use in the 'From' field (e.g., 'Acme Corp')",
        value_type: :string,
        default_value: nil,
        required: false,
        validation_fn: nil
      },
      %{
        name: :smtp_use_ssl,
        description: "Use SSL/TLS for SMTP connection",
        value_type: :boolean,
        default_value: true,
        required: false,
        validation_fn: nil
      }
    ]
  end

  @impl true
  def validate_value(setting_name, value) do
    setting = Authify.Configurations.Schema.get_setting(__MODULE__, setting_name)

    if setting do
      with {:ok, casted_value} <-
             Authify.Configurations.Schema.cast_value(setting.value_type, value) do
        run_validation(setting, casted_value)
      end
    else
      {:error, "unknown setting: #{setting_name}"}
    end
  end

  @doc """
  Validates email_link_domain with organization context.

  This is a special validation that requires the organization to check
  if the domain is in the allowed list.
  """
  def validate_email_link_domain(org, value) do
    if value == nil or value == "" do
      {:ok, nil}
    else
      allowed = Authify.Organizations.get_allowed_domains(org)

      if value in allowed do
        {:ok, value}
      else
        {:error,
         "must be one of the allowed domains: #{Enum.join(allowed, ", ")}. Configure CNAMEs or tenant base domain first."}
      end
    end
  end

  @doc """
  Validates a rate limit setting with organization context.

  Ensures that the value does not exceed the corresponding quota setting.
  """
  def validate_rate_limit_with_quota(org, setting_name, value) do
    # Map setting name to quota name
    quota_name =
      case setting_name do
        :auth_rate_limit -> :quota_auth_rate_limit
        :oauth_rate_limit -> :quota_oauth_rate_limit
        :saml_rate_limit -> :quota_saml_rate_limit
        :api_rate_limit -> :quota_api_rate_limit
        _ -> nil
      end

    if quota_name do
      # Get the quota value for this organization
      quota = Authify.Configurations.get_organization_setting(org, quota_name)

      cond do
        value == nil ->
          {:ok, nil}

        quota == nil ->
          {:error, "Quota not set for this organization"}

        value > quota ->
          {:error, "Must be less than or equal to quota (#{quota})"}

        value > 0 ->
          {:ok, value}

        true ->
          {:error, "Must be a positive integer"}
      end
    else
      # Not a rate limit setting, just validate it's positive
      validate_positive_integer(value)
    end
  end

  defp run_validation(%{validation_fn: nil}, value), do: {:ok, value}

  defp run_validation(%{validation_fn: validation_fn}, value) when is_function(validation_fn) do
    validation_fn.(value)
  end

  defp validate_description(nil), do: {:ok, nil}
  defp validate_description(""), do: {:ok, nil}

  defp validate_description(value) when is_binary(value) do
    if String.length(value) <= 1000 do
      {:ok, value}
    else
      {:error, "Description must be 1000 characters or less"}
    end
  end

  defp validate_description(_), do: {:error, "Description must be a string"}

  defp validate_url(nil), do: {:ok, nil}
  defp validate_url(""), do: {:ok, nil}

  defp validate_url(value) when is_binary(value) do
    if String.match?(value, ~r/^https?:\/\/.+/) do
      {:ok, value}
    else
      {:error, "Must be a valid URL starting with http:// or https://"}
    end
  end

  defp validate_url(_), do: {:error, "URL must be a string"}

  defp validate_email(nil), do: {:ok, nil}
  defp validate_email(""), do: {:ok, nil}

  defp validate_email(value) when is_binary(value) do
    if String.match?(value, ~r/^[^\s]+@[^\s]+\.[^\s]+$/) do
      {:ok, value}
    else
      {:error, "Must be a valid email address"}
    end
  end

  defp validate_email(_), do: {:error, "Email must be a string"}

  defp validate_smtp_server(nil), do: {:ok, nil}
  defp validate_smtp_server(""), do: {:ok, nil}

  defp validate_smtp_server(value) when is_binary(value) do
    # Basic hostname validation - allow alphanumeric, hyphens, and dots
    if String.match?(
         value,
         ~r/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-Z-]{0,61}[a-zA-Z0-9])?)*$/
       ) do
      {:ok, value}
    else
      {:error, "Must be a valid hostname"}
    end
  end

  defp validate_smtp_server(_), do: {:error, "SMTP server must be a string"}

  defp validate_smtp_port(nil), do: {:ok, nil}

  defp validate_smtp_port(port) when is_integer(port) do
    if port > 0 and port <= 65_535 do
      {:ok, port}
    else
      {:error, "Must be a valid port number (1-65535)"}
    end
  end

  defp validate_smtp_port(_), do: {:error, "SMTP port must be an integer"}

  defp validate_positive_integer(nil), do: {:ok, nil}

  defp validate_positive_integer(value) when is_integer(value) and value > 0 do
    {:ok, value}
  end

  defp validate_positive_integer(value) when is_integer(value) do
    {:error, "Must be a positive integer greater than 0"}
  end

  defp validate_positive_integer(_), do: {:error, "Must be an integer"}
end
