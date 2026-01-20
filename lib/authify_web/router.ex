defmodule AuthifyWeb.Router do
  use AuthifyWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {AuthifyWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug AuthifyWeb.Auth.Pipeline
  end

  pipeline :public_html do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :put_secure_browser_headers
  end

  pipeline :organization do
    plug AuthifyWeb.Plugs.OrganizationPlug
  end

  pipeline :auth do
    plug Guardian.Plug.EnsureAuthenticated
    plug AuthifyWeb.Auth.OrganizationContext
  end

  pipeline :admin do
    plug Guardian.Plug.EnsureAuthenticated
    plug AuthifyWeb.Auth.OrganizationContext, :require_admin
  end

  pipeline :super_admin do
    plug Guardian.Plug.EnsureAuthenticated
    plug AuthifyWeb.Auth.OrganizationContext, :require_super_admin
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  pipeline :management_api do
    plug :accepts, ["json"]
    plug AuthifyWeb.Plugs.RateLimiter, :api_rate_limit
    plug AuthifyWeb.Plugs.ApiVersionNegotiation
    plug AuthifyWeb.Auth.APIAuth
  end

  pipeline :scim do
    plug :accepts, ["json", "scim+json"]
    plug AuthifyWeb.Plugs.RateLimiter, :scim_rate_limit
    plug AuthifyWeb.Auth.APIAuth
    plug AuthifyWeb.Plugs.ScimFeatureToggle
    plug AuthifyWeb.Plugs.SCIMETagValidation
  end

  pipeline :oauth do
    plug :accepts, ["html", "json"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {AuthifyWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug AuthifyWeb.Plugs.RateLimiter, :oauth_rate_limit
    plug AuthifyWeb.Auth.Pipeline
  end

  pipeline :saml do
    plug :accepts, ["html", "xml"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {AuthifyWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug AuthifyWeb.Plugs.RateLimiter, :saml_rate_limit
    plug AuthifyWeb.Auth.Pipeline
  end

  pipeline :auth_endpoints do
    plug AuthifyWeb.Plugs.RateLimiter, :auth_rate_limit
  end

  # Health check endpoint (no authentication, for Kubernetes probes)
  scope "/", AuthifyWeb do
    pipe_through :api

    get "/health", HealthController, :index
  end

  scope "/", AuthifyWeb do
    pipe_through :browser

    get "/", PageController, :home

    # Initial system setup (only when no users exist)
    get "/setup", SetupController, :new
    post "/setup", SetupController, :create

    # Email verification (public routes)
    get "/email/verify/:token", EmailVerificationController, :verify

    # Public invitation acceptance (read-only, no rate limit needed for GET)
    get "/invite/:token", InvitationController, :accept
  end

  # Rate-limited authentication endpoints
  scope "/", AuthifyWeb do
    pipe_through [:browser, :auth_endpoints]

    # Organization signup (rate limited to prevent spam)
    get "/signup", OrganizationController, :new
    post "/signup", OrganizationController, :create
    get "/organizations/:id/success", OrganizationController, :success

    # Authentication (rate limited to prevent brute force)
    get "/login", SessionController, :new
    post "/login", SessionController, :create

    # Password reset (rate limited to prevent abuse)
    get "/password_reset/new", PasswordResetController, :new
    post "/password_reset", PasswordResetController, :create
    get "/password_reset/:token/edit", PasswordResetController, :edit
    put "/password_reset/:token", PasswordResetController, :update

    # Invitation acceptance POST (rate limited)
    post "/invite/:token/accept", InvitationController, :accept_invitation
  end

  # MFA verification during login (requires pending MFA session, not full auth)
  scope "/mfa", AuthifyWeb do
    pipe_through [:browser, :auth_endpoints]

    get "/verify", MfaController, :verify_form
    post "/verify", MfaController, :verify_code
    get "/locked", MfaController, :locked
  end

  # Logout doesn't need rate limiting (it's a DELETE and terminates sessions)
  scope "/", AuthifyWeb do
    pipe_through [:browser, :auth]

    delete "/logout", SessionController, :delete
  end

  # Organization-scoped routes - all application functionality under /:org_slug
  scope "/:org_slug", AuthifyWeb do
    pipe_through [:browser, :organization, :auth]

    # Dashboard - admin view for admins, user view for regular users
    get "/dashboard", DashboardController, :index

    # User dashboard - applications available to the user
    get "/user/dashboard", UserDashboardController, :index

    # Application link proxy - validates permissions before redirect
    get "/user/apps/oauth2/:app_id", AppLinkController, :oauth2
    get "/user/apps/saml/:sp_id", AppLinkController, :saml

    # User profile management
    get "/profile", ProfileController, :show
    get "/profile/edit", ProfileController, :edit
    patch "/profile", ProfileController, :update
    get "/profile/password", ProfileController, :edit_password
    patch "/profile/password", ProfileController, :update_password
    post "/profile/resend-verification", ProfileController, :resend_verification
    get "/profile/personal-access-tokens", ProfileController, :personal_access_tokens
    post "/profile/personal-access-tokens", ProfileController, :create_personal_access_token
    delete "/profile/personal-access-tokens/:id", ProfileController, :delete_personal_access_token

    # Email management
    get "/profile/emails", ProfileController, :emails
    post "/profile/emails", ProfileController, :add_email
    delete "/profile/emails/:id", ProfileController, :delete_email
    post "/profile/emails/:id/set-primary", ProfileController, :set_primary_email
    post "/profile/emails/:id/resend-verification", ProfileController, :resend_email_verification

    # MFA setup and management
    get "/profile/mfa", MfaController, :show
    get "/profile/mfa/setup", MfaController, :setup
    post "/profile/mfa/setup", MfaController, :complete_setup
    delete "/profile/mfa", MfaController, :disable
    get "/profile/mfa/backup-codes", MfaController, :backup_codes
    post "/profile/mfa/regenerate-codes", MfaController, :regenerate_codes
    get "/profile/mfa/devices", MfaController, :list_devices
    delete "/profile/mfa/devices/:id", MfaController, :revoke_device
    delete "/profile/mfa/devices", MfaController, :revoke_all_devices
  end

  # Admin-only routes - require organization admin privileges
  scope "/:org_slug", AuthifyWeb do
    pipe_through [:browser, :organization, :admin]

    # Organization settings
    get "/settings", OrganizationSettingsController, :show
    get "/settings/management-api", OrganizationSettingsController, :management_api

    get "/settings/management-api/new",
        OrganizationSettingsController,
        :new_management_api_app

    post "/settings/management-api",
         OrganizationSettingsController,
         :create_management_api_app

    patch "/settings/management-api/:id",
          OrganizationSettingsController,
          :update_management_api_app

    delete "/settings/management-api/:id",
           OrganizationSettingsController,
           :delete_management_api_app

    # Configuration management (uses Global schema for authify-global, Organization schema for others)
    get "/settings/configuration", ConfigurationController, :show
    patch "/settings/configuration", ConfigurationController, :update

    # User management (works for both regular and global organizations)
    resources "/users", UsersController, only: [:index, :show, :new, :create, :edit, :update]
    patch "/users/:id/promote_global", UsersController, :promote_to_global_admin
    patch "/users/:id/demote_global", UsersController, :demote_from_global_admin
    patch "/users/:id/role/:role", UsersController, :update_role
    post "/users/:id/reset_password", UsersController, :force_password_reset
    patch "/users/:id/disable", UsersController, :disable_user
    patch "/users/:id/enable", UsersController, :enable_user
    post "/users/:id/mfa/unlock", UsersController, :unlock_mfa
    post "/users/:id/mfa/reset", UsersController, :reset_mfa

    # Invitations management
    resources "/invitations", InvitationController, only: [:index, :new, :create, :show, :delete]

    # Audit Logs (admin only)
    resources "/audit_logs", AuditLogsController, only: [:index, :show]

    # OAuth Applications management
    resources "/applications", ApplicationsController

    # SAML Service Providers management
    resources "/saml_providers", SAMLProvidersController

    # Certificate management for IdP signing
    resources "/certificates", CertificatesController
    get "/certificates/:id/download/:type", CertificatesController, :download
    patch "/certificates/:id/activate", CertificatesController, :activate
    patch "/certificates/:id/deactivate", CertificatesController, :deactivate

    # Groups management
    resources "/groups", GroupController
    get "/groups/:id/members", GroupController, :manage_members
    post "/groups/:id/users", GroupController, :add_user
    delete "/groups/:id/users/:user_id", GroupController, :remove_user
    post "/groups/:id/applications", GroupController, :add_application
    delete "/groups/:id/applications/:member_id", GroupController, :remove_application

    # SCIM Clients (outbound provisioning)
    resources "/scim_clients", ScimClientsController
    get "/scim_clients/:id/logs", ScimClientsController, :logs
  end

  # Super admin only routes - require global admin privileges
  scope "/:org_slug", AuthifyWeb do
    pipe_through [:browser, :organization, :super_admin]

    # Organization switching for global admins
    post "/switch/global", OrganizationSwitchController, :switch_to_global
    post "/switch/organization/:slug", OrganizationSwitchController, :switch_to_organization

    # Organization management (only accessible when in global organization)
    resources "/organizations", OrganizationsController,
      only: [:index, :show, :new, :create, :edit, :update, :delete]

    post "/organizations/:id/switch", OrganizationsController, :switch_to_organization
    patch "/organizations/:id/disable", OrganizationsController, :disable
    patch "/organizations/:id/enable", OrganizationsController, :enable

    # Analytics and maintenance (only accessible when in global organization)
    get "/analytics", AnalyticsController, :index
    get "/maintenance", MaintenanceController, :index
    post "/maintenance/cleanup_invitations", MaintenanceController, :cleanup_expired_invitations

    post "/maintenance/cleanup_organizations",
         MaintenanceController,
         :cleanup_inactive_organizations

    post "/maintenance/recalculate_stats", MaintenanceController, :recalculate_stats
  end

  # OAuth2/OIDC endpoints (organization-scoped)
  scope "/:org_slug/oauth", AuthifyWeb do
    pipe_through [:oauth, :organization]

    get "/authorize", OAuthController, :authorize
    post "/consent", OAuthController, :consent
  end

  scope "/:org_slug/oauth", AuthifyWeb do
    pipe_through [:api, :organization]

    post "/token", OAuthController, :token
    get "/userinfo", OAuthController, :userinfo
  end

  # Management API for programmatic access (organization-scoped)
  scope "/:org_slug/api", AuthifyWeb.API do
    pipe_through [:organization, :management_api]

    # Organization Management
    get "/organization", OrganizationController, :show
    get "/organization/configuration", OrganizationController, :configuration
    put "/organization/configuration", OrganizationController, :update_configuration

    # User Management
    get "/users", UsersController, :index
    post "/users", UsersController, :create
    get "/users/:id", UsersController, :show
    put "/users/:id", UsersController, :update
    delete "/users/:id", UsersController, :delete
    put "/users/:id/role", UsersController, :update_role
    get "/users/:id/mfa", UsersController, :mfa_status
    post "/users/:id/mfa/unlock", UsersController, :mfa_unlock
    post "/users/:id/mfa/reset", UsersController, :mfa_reset

    # Invitation Management
    get "/invitations", InvitationsController, :index
    post "/invitations", InvitationsController, :create
    get "/invitations/:id", InvitationsController, :show
    put "/invitations/:id", InvitationsController, :update
    delete "/invitations/:id", InvitationsController, :delete

    # OAuth Application Management
    get "/applications", ApplicationsController, :index
    post "/applications", ApplicationsController, :create
    get "/applications/:id", ApplicationsController, :show
    put "/applications/:id", ApplicationsController, :update
    delete "/applications/:id", ApplicationsController, :delete

    post "/applications/:application_id/regenerate-secret",
         ApplicationsController,
         :regenerate_secret

    # SAML Service Provider Management
    get "/saml-providers", SAMLProvidersController, :index
    post "/saml-providers", SAMLProvidersController, :create
    get "/saml-providers/:id", SAMLProvidersController, :show
    put "/saml-providers/:id", SAMLProvidersController, :update
    delete "/saml-providers/:id", SAMLProvidersController, :delete

    # Certificate Management
    get "/certificates", CertificatesController, :index
    post "/certificates", CertificatesController, :create
    get "/certificates/:id", CertificatesController, :show
    put "/certificates/:id", CertificatesController, :update
    delete "/certificates/:id", CertificatesController, :delete
    patch "/certificates/:id/activate", CertificatesController, :activate
    patch "/certificates/:id/deactivate", CertificatesController, :deactivate
    get "/certificates/:id/download/:type", CertificatesController, :download

    # SCIM Client Management (Outbound Provisioning)
    get "/scim-clients", ScimClientsController, :index
    post "/scim-clients", ScimClientsController, :create
    get "/scim-clients/:id", ScimClientsController, :show
    put "/scim-clients/:id", ScimClientsController, :update
    delete "/scim-clients/:id", ScimClientsController, :delete
    post "/scim-clients/:scim_client_id/sync", ScimClientsController, :trigger_sync
    get "/scim-clients/:scim_client_id/logs", ScimClientsController, :logs

    # Group Management
    get "/groups", GroupsController, :index
    post "/groups", GroupsController, :create
    get "/groups/:id", GroupsController, :show
    put "/groups/:id", GroupsController, :update
    delete "/groups/:id", GroupsController, :delete
    get "/groups/:id/members", GroupsController, :members
    post "/groups/:id/users", GroupsController, :add_user
    delete "/groups/:id/users/:user_id", GroupsController, :remove_user
    post "/groups/:id/applications", GroupsController, :add_application
    delete "/groups/:id/applications/:member_id", GroupsController, :remove_application

    # Profile Management (user's own profile)
    get "/profile", ProfileController, :show
    put "/profile", ProfileController, :update

    # Audit Logs (read-only)
    get "/audit-logs", AuditLogsController, :index
    get "/audit-logs/:id", AuditLogsController, :show
  end

  # SCIM 2.0 endpoints for user provisioning (organization-scoped, RFC 7644)
  scope "/:org_slug/scim/v2", AuthifyWeb.SCIM do
    pipe_through [:organization, :scim]

    # Discovery endpoints
    get "/ServiceProviderConfig", ServiceProviderConfigController, :show
    get "/ResourceTypes", ResourceTypesController, :index
    get "/ResourceTypes/:id", ResourceTypesController, :show
    get "/Schemas", SchemasController, :index
    get "/Schemas/:id", SchemasController, :show

    # Bulk operations endpoint (RFC 7644 Section 3.7)
    post "/Bulk", BulkController, :create

    # /Me endpoint for authenticated user self-service (RFC 7644 Section 3.11)
    # Note: DELETE not supported - users cannot self-deactivate per security policy
    get "/Me", MeController, :show
    put "/Me", MeController, :update
    patch "/Me", MeController, :patch

    # Users resource endpoints (Phase 5)
    get "/Users", UsersController, :index
    post "/Users", UsersController, :create
    get "/Users/:id", UsersController, :show
    put "/Users/:id", UsersController, :update
    patch "/Users/:id", UsersController, :patch
    delete "/Users/:id", UsersController, :delete

    # Groups resource endpoints
    get "/Groups", GroupsController, :index
    post "/Groups", GroupsController, :create
    get "/Groups/:id", GroupsController, :show
    put "/Groups/:id", GroupsController, :update
    patch "/Groups/:id", GroupsController, :patch
    delete "/Groups/:id", GroupsController, :delete
  end

  # OIDC Discovery endpoint (organization-scoped, RFC-compliant)
  scope "/:org_slug/.well-known", AuthifyWeb do
    pipe_through [:api, :organization]

    get "/openid-configuration", OIDCController, :discovery
    get "/jwks", OIDCController, :jwks
  end

  # SAML Identity Provider endpoints (organization-scoped)
  scope "/:org_slug/saml", AuthifyWeb do
    pipe_through [:saml, :organization]

    get "/metadata", SAMLController, :metadata
    get "/sso", SAMLController, :sso
    post "/sso", SAMLController, :sso
    get "/continue/:session_id", SAMLController, :continue
    get "/slo", SAMLController, :slo
    post "/slo", SAMLController, :slo
  end

  # Public API documentation
  scope "/docs", AuthifyWeb.API do
    pipe_through :api

    get "/openapi.json", DocsController, :openapi
  end

  # Interactive API documentation UI
  scope "/" do
    pipe_through :public_html

    get "/docs/api", ScalarPlug,
      path: "/docs/api",
      spec_href: "/docs/openapi.json",
      title: "Authify API Documentation"
  end

  # Other scopes may use custom stacks.
  # scope "/api", AuthifyWeb do
  #   pipe_through :api
  # end

  # Enable LiveDashboard and Swoosh mailbox preview in development
  if Application.compile_env(:authify, :dev_routes) do
    # If you want to use the LiveDashboard in production, you should put
    # it behind authentication and allow only admins to access it.
    # If your application does not have an admins-only section yet,
    # you can use Plug.BasicAuth to set up some basic authentication
    # as long as you are also using SSL (which you should anyway).
    import Phoenix.LiveDashboard.Router

    scope "/dev" do
      pipe_through :browser

      live_dashboard "/dashboard", metrics: AuthifyWeb.Telemetry
      forward "/mailbox", Plug.Swoosh.MailboxPreview
    end
  end

  # Note: Prometheus metrics are exposed on port 9568 at /metrics
  # by TelemetryMetricsPrometheus (configured in Authify.Telemetry)
end
