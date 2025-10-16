# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/authify/authify/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/authify/authify/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/authify/authify/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/authify/authify/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/authify/authify/releases/tag/v0.1.0
