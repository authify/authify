defmodule Authify.Configurations.Schemas.Global do
  @moduledoc """
  Configuration schema for global system settings.

  These settings control system-wide behavior and are stored
  in the authify-global organization's configuration.
  """

  @behaviour Authify.Configurations.Schema

  @impl true
  def schema_name, do: "global"

  @impl true
  def settings do
    [
      %{
        name: :allow_organization_registration,
        description:
          "Allow new organizations to self-register. When false, only super admins can create organizations.",
        value_type: :boolean,
        default_value: false,
        required: true,
        validation_fn: nil
      },
      %{
        name: :site_name,
        description: "The name of this Authify instance displayed in the UI",
        value_type: :string,
        default_value: "Authify",
        required: false,
        validation_fn: nil
      },
      %{
        name: :support_email,
        description: "Support email address shown to users",
        value_type: :string,
        default_value: nil,
        required: false,
        validation_fn: &validate_email/1
      },
      %{
        name: :tenant_base_domain,
        description:
          "Base domain for tenant subdomains (e.g., 'authify.example.com'). Organizations will be accessible at {org-slug}.{tenant_base_domain}. This setting is required and cannot be removed once set.",
        value_type: :string,
        default_value: nil,
        required: true,
        validation_fn: &validate_domain_required/1
      },
      %{
        name: :email_link_domain,
        description:
          "Domain used in email links for the global organization (invitations, password reset, etc.). Must be either authify-global.{tenant_base_domain} or one of its configured CNAMEs.",
        value_type: :string,
        default_value: nil,
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

  defp run_validation(%{validation_fn: nil}, value), do: {:ok, value}

  defp run_validation(%{validation_fn: validation_fn}, value) when is_function(validation_fn) do
    validation_fn.(value)
  end

  defp validate_email(nil), do: {:ok, nil}
  defp validate_email(""), do: {:ok, nil}

  defp validate_email(email) when is_binary(email) do
    if String.match?(email, ~r/^[^\s@]+@[^\s@]+\.[^\s@]+$/) do
      {:ok, email}
    else
      {:error, "must be a valid email address"}
    end
  end

  defp validate_domain_required(nil),
    do: {:error, "tenant base domain is required and cannot be empty"}

  defp validate_domain_required(""),
    do: {:error, "tenant base domain is required and cannot be empty"}

  defp validate_domain_required(domain) when is_binary(domain) do
    # Normalize to lowercase for consistency
    normalized = String.downcase(domain)

    # Validate domain format: lowercase alphanumeric with hyphens and dots
    # Max 253 chars total, max 63 chars per label
    if String.match?(
         normalized,
         ~r/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/
       ) and
         String.length(normalized) <= 253 do
      {:ok, normalized}
    else
      {:error, "must be a valid domain name"}
    end
  end
end
