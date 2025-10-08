defmodule Authify.Scopes do
  @moduledoc """
  Centralized scope definitions and validation for the application.

  Scopes control access to various parts of the API and are used by:
  - Personal Access Tokens
  - OAuth Applications (Management API apps)
  - Authorization codes and access tokens
  """

  @oauth_scopes [
    "openid",
    "profile",
    "email"
  ]

  @management_api_scopes [
    # Management API OAuth apps
    "management_app:read",
    "management_app:write",
    # User management
    "users:read",
    "users:write",
    # Invitation management
    "invitations:read",
    "invitations:write",
    # OAuth application management
    "applications:read",
    "applications:write",
    # Application group management
    "application_groups:read",
    "application_groups:write",
    # SAML service provider management
    "saml:read",
    "saml:write",
    # Certificate management
    "certificates:read",
    "certificates:write",
    # Organization configuration
    "organizations:read",
    "organizations:write"
  ]

  # Profile scopes are only for Personal Access Tokens
  @pat_only_scopes [
    "profile:read",
    "profile:write"
  ]

  @doc """
  Returns all valid OAuth scopes (openid, profile, email).
  """
  def oauth_scopes, do: @oauth_scopes

  @doc """
  Returns all valid Management API scopes.
  """
  def management_api_scopes, do: @management_api_scopes

  @doc """
  Returns PAT-only scopes (profile:read, profile:write).
  """
  def pat_only_scopes, do: @pat_only_scopes

  @doc """
  Returns all valid scopes for Personal Access Tokens (Management API + PAT-only).
  """
  def pat_scopes, do: @management_api_scopes ++ @pat_only_scopes

  @doc """
  Returns all valid scopes (OAuth + Management API + PAT-only).
  """
  def all_valid_scopes, do: @oauth_scopes ++ @management_api_scopes ++ @pat_only_scopes

  @doc """
  Checks if a scope is a valid OAuth scope.
  """
  def valid_oauth_scope?(scope), do: scope in @oauth_scopes

  @doc """
  Checks if a scope is a valid Management API scope.
  """
  def valid_management_api_scope?(scope), do: scope in @management_api_scopes

  @doc """
  Checks if a scope is valid (either OAuth or Management API).
  """
  def valid_scope?(scope), do: scope in all_valid_scopes()

  @doc """
  Returns a map of scopes grouped by category for UI display.
  """
  def scopes_by_category do
    %{
      "OAuth/OIDC" => [
        {"openid", "OpenID Connect authentication"},
        {"profile", "Read user profile information"},
        {"email", "Read user email address"}
      ],
      "User Management" => [
        {"users:read", "Read user information in organization"},
        {"users:write", "Manage users in organization"}
      ],
      "Invitations" => [
        {"invitations:read", "Read invitations in organization"},
        {"invitations:write", "Manage invitations in organization"}
      ],
      "Applications" => [
        {"applications:read", "Read OAuth applications in organization"},
        {"applications:write", "Manage OAuth applications in organization"}
      ],
      "Application Groups" => [
        {"application_groups:read", "Read application groups in organization"},
        {"application_groups:write", "Manage application groups in organization"}
      ],
      "SAML" => [
        {"saml:read", "Read SAML service providers in organization"},
        {"saml:write", "Manage SAML service providers in organization"}
      ],
      "Certificates" => [
        {"certificates:read", "Read certificates in organization"},
        {"certificates:write", "Manage certificates in organization"}
      ],
      "Organizations" => [
        {"organizations:read", "Read organization configuration and settings"},
        {"organizations:write", "Manage organization configuration and settings"}
      ],
      "Profile" => [
        {"profile:read", "Read your own profile information"},
        {"profile:write", "Update your own profile information"}
      ],
      "Management API" => [
        {"management_app:read", "Read Management API OAuth apps"},
        {"management_app:write", "Manage Management API OAuth apps"}
      ]
    }
  end
end
