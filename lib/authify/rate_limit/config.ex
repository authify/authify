defmodule Authify.RateLimit.Config do
  @moduledoc """
  Helper module for retrieving rate limit configuration for organizations.

  Implements hierarchical rate limiting where:
  - Organization-specific limits (if set) are used first
  - Falls back to quota settings if org limit is nil
  - Quotas are enforced as upper bounds per organization
  """

  alias Authify.Configurations

  @doc """
  Gets the effective rate limit for an organization and scope.

  ## Logic

  1. Check org-specific setting (e.g., :auth_rate_limit)
  2. If nil, fall back to quota setting (e.g., :quota_auth_rate_limit)
  3. Quota should never be nil (has defaults in schema)

  ## Parameters

  - `org` - The organization struct
  - `scope` - The rate limit scope (:auth, :oauth, :saml, or :api)

  ## Returns

  `{limit, scale_ms}` where limit is requests allowed and scale_ms is the time window

  ## Examples

      iex> Config.get_limit(org, :auth)
      {10, 60_000}

      iex> Config.get_limit(org, :oauth)
      {60, 60_000}
  """
  def get_limit(org, scope) when scope in [:auth, :oauth, :saml, :api] do
    setting_name = :"#{scope}_rate_limit"
    quota_name = :"quota_#{scope}_rate_limit"

    # Try org-specific limit first
    limit = Configurations.get_organization_setting(org, setting_name)

    # Fall back to quota
    effective_limit = limit || Configurations.get_organization_setting(org, quota_name)

    # Default to 60 second window
    {effective_limit, 60_000}
  end

  @doc """
  Gets the quota (maximum allowed limit) for an organization and scope.

  This is useful for displaying the maximum value to administrators.

  ## Parameters

  - `org` - The organization struct
  - `scope` - The rate limit scope (:auth, :oauth, :saml, or :api)

  ## Returns

  The quota value as an integer

  ## Examples

      iex> Config.get_quota(org, :auth)
      10

      iex> Config.get_quota(org, :oauth)
      60
  """
  def get_quota(org, scope) when scope in [:auth, :oauth, :saml, :api] do
    quota_name = :"quota_#{scope}_rate_limit"
    Configurations.get_organization_setting(org, quota_name)
  end

  @doc """
  Gets the configured (non-quota) rate limit for an organization and scope.

  Returns nil if not explicitly set, indicating the quota value should be used.

  ## Parameters

  - `org` - The organization struct
  - `scope` - The rate limit scope (:auth, :oauth, :saml, or :api)

  ## Returns

  The configured limit or nil

  ## Examples

      iex> Config.get_configured_limit(org, :auth)
      5  # org admin set a custom limit

      iex> Config.get_configured_limit(org, :oauth)
      nil  # using quota default
  """
  def get_configured_limit(org, scope) when scope in [:auth, :oauth, :saml, :api] do
    setting_name = :"#{scope}_rate_limit"
    Configurations.get_organization_setting(org, setting_name)
  end
end
