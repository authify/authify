# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.1] - 2025-12-24

### Added

- **SAML Provider Management API Documentation**
  - Comprehensive OpenAPI documentation for SAML provider endpoints (GET, POST, PUT, DELETE)
  - Detailed examples showing mustache-style attribute mapping templates
  - Request/response schemas with full field descriptions
  - Security scopes and authentication requirements documented

## [0.8.0] - 2025-12-24

### Added

- **Mustache-style template interpolation for SAML attribute mapping**
  - True regex-based `{{field_name}}` placeholder parsing for SAML attributes
  - Support for complex multi-field templates like `"{{first_name}} {{last_name}}"`
  - Smart handling of multi-valued attributes (e.g., groups) - returns list directly when `{{groups}}` is the sole template
  - Graceful handling of nil values and whitespace in placeholders
  - Updated default SAML attribute mapping to use new mustache format
  - Comprehensive test coverage with 8 new test cases for template interpolation
  - All 730 tests passing

## [0.7.1] - 2025-12-22

### Added

- **OIDC groups claim support** in OAuth2/OIDC userinfo endpoint
  - New `groups` scope returns array of user's group names
  - Matches SAML groups attribute implementation for consistency
  - Efficient group preloading when scope is requested
  - Standard OIDC claim compatible with most identity-aware applications
  - Comprehensive test coverage for groups claim scenarios

## [0.7.0] - 2025-12-22

### Added

- Username support in user creation and editing forms
  - Optional field, unique per organization
  - Displayed in user profile and user lists
  - Can be set during user creation or updated later
- Admin user editing capabilities
  - Admins can now edit other users' names, usernames, and emails
  - Full edit form with validation and error handling
  - Proper permission checks (admin or global admin required)
  - Edit buttons added to user detail and index pages
  - Audit logging for all user updates
- Email verification security enhancement
  - Email verification is automatically cleared when email address changes
  - Applies to both admin-initiated and self-service profile updates
  - Prevents security bypass via email change
  - Comprehensive test coverage for verification reset behavior
- Groups system for application access management
  - Replaces legacy ApplicationGroups with new Groups model
  - Many-to-many relationships with users via GroupMembership join table
  - Polymorphic ApplicationAssignment for both OAuth2 and SAML applications
  - Complete CRUD interface for group management
  - Member management UI for adding/removing users and applications
  - SAML group membership attributes in SAML assertions

### Changed

- Consolidated Groups system architecture
  - Removed legacy ApplicationGroups (2,522 lines of code removed)
  - Navigation updated to remove ApplicationGroups references
  - Groups now support both OAuth and SAML applications in a unified model
  - Simplified data model with clearer relationships

### Fixed

- Fixed template bugs in group views accessing nested user fields
  - Group show and manage_members templates now correctly access User objects
  - Resolved "key :user_groups not found" errors

## [0.6.4] - 2025-12-20

### Fixed

- Fixed critical configuration settings bugs that prevented organization settings from being saved
  - Fixed KeyError when accessing user.global_admin field by calling User.global_admin?/1 function instead
  - Fixed type comparison issue where string form values were compared to integer quota values
    - In Elixir's term ordering, strings are always greater than integers, causing validation to incorrectly fail
    - Added proper type casting before comparison in validate_rate_limit_with_quota/3
  - Fixed empty string handling for rate limit settings
    - Empty strings are now properly treated as nil (not set), allowing fallback to quota defaults
    - Users can now leave rate limit fields blank to use the organization's quota value

## [0.6.3] - 2025-12-18

### Fixed

- Fixed critical UX bug where personal access tokens were not displayed after creation
  - Controller now passes plaintext token instead of hashed value to flash
  - Template now uses correct string keys to access flash values
  - Removed confusing hashed token display from existing tokens list
  - Improved dark mode styling for token display box
- Fixed Management API audit logs endpoint JSON serialization errors
  - Added Jason.Encoder derivation to AuditLog.Event schema
  - Fixed pagination by converting page/per_page to limit/offset
  - Added URL pluralization rule for consistent hyphenated URLs
- Fixed FunctionClauseError in User.super_admin?/1 when called with service account maps
  - Added catch-all clause to handle non-User struct values
- Added comprehensive test suite for audit logs API endpoints (12 tests)

## [0.6.2] - 2025-12-17

### Fixed

- Static assets were not being included in the Docker image, causing 404s for images
  - Updated .dockerignore to allow `/priv/static` to make it to the final image

## [0.6.1] - 2025-12-17

### Fixed

- Corrected OpenAPI schema references for collection links in API documentation
  - Updated `links` property in collection responses to reference `CollectionLinks` schema
  - Fixed incorrect reference to `HateoasLink` schema
- Fully switched to Kubernetes DNS-based clustering for Erlang nodes
  - Removed RBAC configuration and dependencies
  - Simplified deployment manifests by eliminating `rbac.yaml` and related settings
  - Updated documentation to reflect DNS-based clustering setup

## [0.6.0] - 2025-12-17

### Added

- Initial support for Kubernetes RBAC-based clustering with libcluster
  - Uses Kubernetes API strategy for node discovery
  - Requires ServiceAccount with permissions to list/watch pods in the namespace
  - Configured via environment variables:
    - `RELEASE_NAMESPACE`: Namespace where Authify is deployed
    - `CLUSTER_SERVICE_NAME`: Headless service name for DNS resolution
    - `RELEASE_NODE`: Pod name of the current node (set via downward API)
    - `POD_NAME`: Pod name of the current node (set via downward API)
  - Updated Kubernetes manifests:
    - Renamed headless service to `authify-internal` for clustering
    - Created Role and RoleBinding for pod reading permissions
    - Set environment variables in ConfigMap and Deployment
  - Documentation updated in `k8s/README.md` with setup instructions
- Fixed usage of `Mix.env()` in production code to use `Application.get_env()` instead
- API documentation base URL is now configurable via `API_BASE_URL` environment variable

## [0.5.0] - 2025-12-17

### Added

- Health check endpoint at `/health` for Kubernetes liveness and readiness probes
  - Verifies application and database connectivity
  - Returns 200 OK when healthy, 503 Service Unavailable when unhealthy
  - 1-second response caching to prevent database connection pool exhaustion
  - ETS-based cache for high-performance and thread-safe operation
  - No authentication required (designed for infrastructure monitoring)
  - Comprehensive test coverage including cache behavior and concurrent requests

## [0.4.2] - 2025-12-16

### Fixed

- Fixed UndefinedFunctionError in production by replacing Mix.env() with Application.get_env() in prometheus_children/0
- Updated Guardian configuration to use environment variables (GUARDIAN_SECRET_KEY or SECRET_KEY_BASE)

## [0.4.1] - 2025-12-16

### Changed

- Updated Docker build action to v6 in GitHub release workflow

## [0.4.0] - 2025-12-04

### Changed
- Updated Elixir from 1.18.4 to 1.19.4
- Updated Erlang/OTP from 27.3.4.2 to 28.2
- Updated 13 dependencies to latest versions:
  - Phoenix 1.8.1 → 1.8.2
  - Phoenix LiveView 1.1.14 → 1.1.18
  - Phoenix Ecto 4.6.5 → 4.7.0
  - Ecto 3.13.3 → 3.13.5
  - And 9 other packages
- Replaced manual ASN.1 certificate generation in test fixtures with X509 library for OTP 28 compatibility
- Fixed code quality issues: replaced inefficient length/1 checks with Enum.empty?/1

### Added
- Comprehensive release process documentation in CONTRIBUTING.md
  - Step-by-step release checklist
  - Version numbering guidelines
  - Automated GitHub Actions release workflow documentation
  - Common issues and troubleshooting

## [0.3.0] - 2025-10-22

### Changed
- **BREAKING:** `SAML.Certificate.private_key` field now uses `Authify.Encrypted.Binary` type
  - Private keys are now encrypted at rest using AES-256-GCM
  - Existing plaintext private keys in `saml_certificates` table are incompatible and must be re-imported
  - Private keys are excluded from JSON serialization to prevent accidental exposure

### Security
- **SECURITY FIX:** SAML certificate private keys are now encrypted at rest
  - Previously stored as plaintext in database
  - Now encrypted using same mechanism as `Accounts.Certificate` and `OAuth.Application.client_secret`
  - Adds comprehensive test coverage for encryption/decryption functionality

### Migration Notes
- For pre-production deployments: Reset database to apply encryption changes
- For production deployments with existing SAML certificates: Manual migration required to encrypt existing private keys
- No migration provided as project is in active development with no production users

## [0.2.0] - 2025-10-15

### Added
- **Comprehensive Audit Logging System** - Complete audit trail for security and compliance
  - 36 event types covering all system operations:
    - Authentication events (login success/failure, logout, session expiry)
    - Password management (reset requested/completed, password changed)
    - Email verification (resent, confirmed)
    - OAuth flows (authorization, consent, token grants/refreshes)
    - SAML operations (SSO, assertion issued, SLO)
    - User management (created, updated, deleted, enabled/disabled)
    - Invitation lifecycle (invited, accepted, revoked)
    - Role changes (assigned, revoked)
    - OAuth client management (created, updated, deleted, secret regenerated)
    - SAML service provider management (created, updated, deleted)
    - Application group management (created, updated, deleted)
    - Organization management (created, updated, deleted)
    - Certificate lifecycle (created, activated, deactivated, deleted)
    - Personal access token management (created, deleted)
    - Settings changes, rate limit exceeded, permission/scope denied
    - API access, API key management, suspicious activity
  - Polymorphic actor support (user, API client, application, system)
  - Organization-scoped with multi-tenant isolation
  - Async event logging for high performance
  - Web UI audit logging for all user-facing operations
  - Management API audit logging with full parity
  - Audit logs API endpoint with comprehensive filtering:
    - Filter by event type, actor, resource, outcome, date range
    - Pagination support (configurable per_page, max 100)
    - New `audit_logs:read` OAuth scope
    - Organization-scoped access control
  - OpenAPI documentation for audit logs API
  - 728 passing tests with comprehensive coverage

### Changed
- Enhanced AuditHelper with additional logging functions for API operations
- Updated all Management API controllers with audit logging
- Improved email verification resend with success/failure audit tracking
- Added source metadata ("web" vs "api") to distinguish event origins

## [0.1.2] - 2025-10-09

### Fixed
- Code formatting in footer layout (HEEx formatting compliance)

## [0.1.1] - 2025-10-09

### Added
- GitHub issue templates (bug report, feature request, security, documentation)
- GitHub pull request template with comprehensive checklist
- Version badge in README.md
- Version display in application footer
- CHANGELOG.md for tracking releases

### Changed
- Updated GitHub release workflow to use `gh` CLI instead of deprecated action
- Improved CI to require credo and sobelow checks to pass

### Fixed
- Code quality improvements to satisfy `mix credo --strict`
- Resolved 101 code style issues (documentation, naming conventions, refactoring)

## [0.1.0] - 2025-10-09

Initial release of Authify - Multi-tenant Identity Provider

### Core Features

#### Multi-tenancy
- Organization-scoped data isolation with MySQL backend
- Custom domain mapping per organization
- Subdomain-based tenant resolution
- Path-based tenant fallback
- Global "authify-global" organization for system-wide settings

#### Authentication & User Management
- Organization signup flow with admin account creation
- Secure user login/logout with session management
- User invitation system with email-based onboarding
- Role-based access control (admin, user, global admin)
- Comprehensive user profile management (view, edit, password change)
- Password complexity validation and security requirements
- Password reset flow with email delivery and secure tokens

#### OAuth2/OIDC Identity Provider
- Complete OAuth2 authorization code flow implementation
- OAuth application registration and management
- Consent screen with scope selection
- JWT access token and ID token generation
- OIDC discovery endpoint (`/.well-known/openid_configuration`)
- JWKS endpoint for public key distribution
- Userinfo endpoint with claims mapping
- Organization-scoped OAuth client management
- Client credentials grant for Management API authentication
- Personal Access Tokens (PATs) for user-specific API access

#### SAML 2.0 Identity Provider
- SAML IdP metadata endpoint (`/saml/metadata`)
- SAML SSO endpoint with HTTP-Redirect and HTTP-POST bindings
- SAML assertion generation with user attributes
- SAML service provider registration and management
- Configurable attribute mapping per service provider
- SAML session management for logout tracking
- SAML Single Logout (SLO) with SP-initiated and IdP-initiated support
- XML digital signatures (RSA-SHA256 with XMLDSig)
- Certificate management with X509 library
- Auto-submit forms for seamless SP integration

#### Admin Dashboard
- Organization management interface (global admin)
- User management with role assignment
- OAuth application management
- SAML service provider management
- System analytics and dashboard
- Invitation management
- Context-sensitive navigation
- Bootstrap 5.3 responsive UI with dark mode support

#### Configuration System
- Polymorphic configuration model with code-based schemas
- Global settings:
  - Organization self-registration control (default: disabled)
  - Site name customization
  - Support email configuration
- Organization-specific settings:
  - User invitation toggle
  - SAML feature toggle
  - OAuth/OIDC feature toggle
  - SMTP configuration with encrypted credentials
  - Email link domain configuration
- Configuration UI via web dashboard
- Configuration API via Management API endpoints
- ETS-based caching with PubSub invalidation

#### Management API
- RESTful API with header-based versioning (`Accept: application/vnd.authify.v1+json`)
- HATEOAS/JSON:API compliant responses
- OAuth2 client credentials authentication
- Comprehensive API endpoints:
  - Organizations
  - Users
  - Invitations
  - OAuth Applications
  - Application Groups
  - SAML Service Providers
  - Certificates
  - Configuration
- OpenAPI 3.1.1 specification (auto-generated)
- Interactive API documentation with Scalar UI
- Scoped access control per endpoint

#### Rate Limiting & DDoS Protection
- Configurable per-organization rate limits
- Hierarchical quota system (super admin quotas + org admin limits)
- ETS-based caching for high-performance lookups
- Multi-tenant rate isolation (auth, OAuth, SAML, API scopes)
- Web UI and API for rate limit configuration
- Automatic cache invalidation on updates

#### Email System
- Organization-specific SMTP configuration
- Encrypted SMTP credentials at rest
- Email types:
  - User invitations with auto-verify
  - Password reset with secure tokens (24h expiry)
  - Email verification for directly-created users (24h expiry)
- HTML and plain text templates
- Development mailbox at `/dev/mailbox`

### Security Features
- CSRF protection (Phoenix built-in)
- Security headers configured
- Secure session management with proper cleanup
- Password complexity requirements with bcrypt hashing
- Token-based authentication (Guardian JWT)
- JWT signature verification with rotating keys
- SAML XML signature verification
- Certificate-based SAML signing
- Rate limiting for authentication endpoints

### Deployment & Infrastructure
- Production-ready Dockerfile with multi-stage build
- Kubernetes deployment manifests:
  - Deployment with health checks
  - Service (HTTP + metrics)
  - Ingress with TLS support
  - HorizontalPodAutoscaler
  - ServiceMonitor for Prometheus
  - ConfigMap and Secret templates
  - Namespace isolation
- Docker Compose for local development
- Health check endpoints
- Prometheus metrics integration (`:9568/metrics`)
- Kubernetes DNS-based clustering support
- Zero-downtime upgrade procedures

### Testing
- Comprehensive test coverage
- OAuth flow integration tests
- SAML flow integration tests
- Multi-tenant isolation tests
- Rate limiting test helpers
- All tests passing with no warnings

### Documentation
- Comprehensive README with:
  - Architecture overview
  - Installation guides (Docker, Docker Compose, Kubernetes)
  - Usage examples (OAuth, SAML, Management API)
  - Configuration reference
  - Security hardening checklist
  - Troubleshooting guide
- Kubernetes deployment documentation (`k8s/README.md`)
- OpenAPI 3.1.1 API specification
- Interactive API documentation (Scalar UI)
- Contributing guidelines
- Security policy with responsible disclosure

### Technical Stack
- Elixir 1.15+ with OTP 25+
- Phoenix 1.8.1 web framework
- MySQL 8.0+ database
- Bootstrap 5.3 with dark mode support
- Phoenix LiveView for interactive components
- Guardian for JWT authentication
- Ecto for database ORM
- Hammer for rate limiting
- X509 for certificate management
- SweetXML for SAML XML processing
- Req for HTTP client operations
- Prometheus metrics with telemetry
- Bandit web server

[Unreleased]: https://github.com/authify/authify/compare/v0.8.1...HEAD
[0.8.1]: https://github.com/authify/authify/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/authify/authify/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/authify/authify/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/authify/authify/compare/v0.6.4...v0.7.0
[0.6.4]: https://github.com/authify/authify/compare/v0.6.3...v0.6.4
[0.6.3]: https://github.com/authify/authify/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/authify/authify/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/authify/authify/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/authify/authify/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/authify/authify/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/authify/authify/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/authify/authify/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/authify/authify/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/authify/authify/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/authify/authify/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/authify/authify/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/authify/authify/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/authify/authify/releases/tag/v0.1.0
