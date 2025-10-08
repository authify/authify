# Authify - Multi-tenant Identity Provider (Elixir/Phoenix Version)

A comprehensive, open-source, multi-tenant identity provider supporting both OAuth2/OIDC and SAML protocols. Built with Elixir and Phoenix 1.8.1.

## Project Requirements

### Core Features
- **Multi-tenant architecture** - Organizations with scoped users and data isolation
- **Organization signup flow** - Self-service organization creation with admin accounts
- **Admin dashboard** - Comprehensive management interface with analytics
- **OAuth2/OIDC Identity Provider** - Full authorization server with consent flows
- **SAML 2.0 Identity Provider** - Enterprise SSO with service provider management
- **User authentication** - Secure login with password complexity requirements
- **User profile management** - Self-service profile and password management
- **Application management** - OAuth client registration and SAML SP configuration
- **Invitation system** - Email-based user onboarding with role assignment
- **Role-based access control** - Organization admins and global administrators

### Technical Stack
- **Elixir** - Latest stable version
- **Phoenix 1.8.1** - Web framework with LiveView
- **MySQL** - Database with proper multi-tenant schema
- **Bootstrap 5.3** - For modern, responsive CSS and JS UI
- **Phoenix LiveView** - For interactive dashboard components
- **Guardian** - JWT authentication
- **Ecto** - Database ORM with migrations

### UI/UX Requirements

- Modern design - Clean, professional interface using Bootstrap layout and components
- Responsive layout - Works on desktop and mobile
- Organization signup - Single form creates org + admin user
- Dashboard layout - Sidebar navigation with stats cards
- Bootstrap-style components - Cards, tables, forms, buttons
- LiveView updates - Changes should show up dynamically where it makes sense
- Intuitive experience - The system must be easy to use and reason about, both for users and admins
- Avoid clutter - make important things easy and make advanced features available via modals or new views

## Current Status

### ✅ **COMPLETED FEATURES**

**Core Infrastructure:**
- ✅ Multi-tenant Phoenix application with MySQL database
- ✅ Bootstrap 5.3 responsive UI with professional design
- ✅ Guardian-based JWT authentication system
- ✅ Organization-scoped data isolation and access control
- ✅ Comprehensive admin dashboard with analytics

**Authentication & User Management:**
- ✅ Organization signup flow with admin account creation
- ✅ Secure user login/logout with session management
- ✅ User invitation system with email-based onboarding
- ✅ Role-based access control (admin, user, global admin)
- ✅ Comprehensive user profile management (view, edit, password change)
- ✅ Password complexity validation and security requirements

**OAuth2/OIDC Identity Provider:**
- ✅ Complete OAuth2 authorization code flow implementation
- ✅ OAuth application registration and management
- ✅ Consent screen with scope selection
- ✅ JWT access token and ID token generation
- ✅ OIDC discovery endpoints (/.well-known/openid_configuration, /jwks)
- ✅ Userinfo endpoint with claims mapping
- ✅ Organization-scoped OAuth client management

**SAML 2.0 Identity Provider:**
- ✅ SAML IdP metadata endpoint (/saml/metadata)
- ✅ SAML SSO endpoint with HTTP-Redirect and HTTP-POST bindings
- ✅ SAML assertion generation with user attributes
- ✅ SAML service provider registration and management
- ✅ Configurable attribute mapping per service provider
- ✅ SAML session management for logout tracking
- ✅ Auto-submit forms for SP integration

**Admin Dashboard:**
- ✅ Organization management (global admin)
- ✅ User management with role assignment
- ✅ OAuth application management
- ✅ SAML service provider management
- ✅ System analytics and maintenance tools
- ✅ Invitation management
- ✅ Context-sensitive navigation

**Configuration System:**
- ✅ Polymorphic configuration model with code-based schemas
- ✅ Global settings (authify-global organization)
  - ✅ Organization self-registration control (default: disabled)
  - ✅ Site name customization
  - ✅ Support email configuration
- ✅ Organization-specific settings
  - ✅ User invitation toggle
  - ✅ SAML feature toggle
  - ✅ OAuth/OIDC feature toggle
- ✅ Configuration UI (web dashboard)
- ✅ Configuration API (Management API endpoints)

**Documentation:**
- ✅ API documentation (OpenAPI/Swagger)

**Password Recovery:**
- ✅ Password reset request flow with email delivery
- ✅ Password reset token generation and validation
- ✅ Password reset form and completion flow
- ✅ Secure password reset email templates (HTML & text)

**SAML Single Logout:**
- ✅ SAML SLO endpoint (/saml/slo)
- ✅ SP-initiated logout request handling
- ✅ IdP-initiated logout support
- ✅ SAML logout response generation
- ✅ Multi-session logout coordination

**Test Coverage:**
- ✅ Comprehensive OAuth and SAML test suites
- ✅ Real-world flow tests for both protocols
- ✅ Multi-tenant isolation tests
- ✅ All tests passing

**Deployment & Infrastructure:**
- ✅ Production Dockerfile with multi-stage build
- ✅ Kubernetes deployment manifests (deployment, service, ingress, HPA, etc.)
- ✅ Kubernetes documentation (k8s/README.md)
- ✅ Docker Compose for local development
- ✅ Health check endpoints
- ✅ Prometheus metrics integration

**Security Features:**
- ✅ CSRF protection (Phoenix built-in)
- ✅ Security headers configured
- ✅ Secure session management
- ✅ Password complexity requirements
- ✅ Token-based authentication (Guardian JWT)

**Rate Limiting & DDoS Protection:**
- ✅ Configurable per-organization rate limits (auth, OAuth, SAML, API endpoints)
- ✅ Hierarchical quota system (super admin quotas + org admin limits)
- ✅ ETS-based caching for high-performance configuration lookups
- ✅ Multi-tenant rate isolation to prevent noisy neighbor issues
- ✅ Web UI for rate limit configuration (quota and limit settings)
- ✅ Management API support via existing configuration endpoints
- ✅ Automatic cache invalidation on configuration updates
- ✅ Test helper system for rate limit testing

### 🔄 **IN PROGRESS**

(No items currently in progress)

### 📋 **PENDING FEATURES**

**Security & Production Readiness:**
- ⏳ Audit logging and security monitoring

**Enterprise Features:**
- ⏳ Advanced SAML features (encryption, complex bindings)
- ⏳ LDAP/Active Directory integration
- ⏳ Multi-factor authentication (MFA)

**Operational:**
- ⏳ Backup and recovery procedures

### 🎯 **PRODUCTION READINESS STATUS**

**Ready for production:**
- ✅ Core identity provider functionality (OAuth2/OIDC + SAML)
- ✅ Multi-tenant architecture
- ✅ Admin management interface
- ✅ Security best practices implemented
- ✅ XML digital signatures (RSA-SHA256 with XMLDSig)
- ✅ Certificate management (X509 library with self-signed generation)
- ✅ Production-grade SAML signing and verification

**Optional enhancements:**
- ⏳ SAML assertion/response encryption (signing is complete)

## Technical Notes

- **Use TDD instead of manual `curl` testing** - Tests reveal issues faster and provide better debugging information
- Use `mix phx.gen` generators to scaffold resources
- Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for commit messages
- **Template error handling** - Use `Keyword.get_values/2` for changeset errors, not direct key access
- **Mixed key consistency** - Keep string vs atom keys consistent in params throughout the pipeline
- **Virtual fields in tests** - Compare specific fields rather than full structs to avoid virtual field mismatches
- **DO NOT COMMIT FAILING TESTS** - Seriously, if tests are failing or the project fails to compile, we're not ready to commit. All tests and style checks must pass before using `git` to commit changes. Use `mix test` or occasionally `mix precommit` to confirm tests pass and style adherence.
- **Treat warnings as failing tests** - When running `mix test`, any warnings (e.g., unused variables) should be considered failures and must be resolved before committing.
- **Finish the task at hand** - Even if it is complex or will be a lot of work, don't suggest stopping, taking a break, taking stock, or anything else to the user related to considering a partially completed task as completed and/or ready to commit. If the user wants to stop, that's fine, but there's no need to suggest it.

### Management API Architecture

- **Header-based versioning** - Uses `Accept: application/vnd.authify.v1+json` or defaults to `application/json` for latest version
- **HATEOAS/JSON:API compliance** - Responses include structured data, links, and metadata following JSON:API patterns
- **Pipeline**: Routes use `:management_api` pipeline with `ApiVersionNegotiation` and `APIAuth` plugs
- **Base controller**: All API controllers inherit from `AuthifyWeb.API.BaseController` for consistent formatting
- **Response structure**:
  ```json
  {
    "data": { "id": "...", "type": "...", "attributes": {...}, "links": {...} },
    "links": { "self": "..." },
    "meta": { "page": 1, "per_page": 25, "total": 100 }
  }
  ```
- **Error format**:
  ```json
  {
    "error": { "type": "...", "message": "...", "details": {...} },
    "links": { "documentation": "/developers/errors" }
  }
  ```

### Management API Development Requirements

**When adding or updating Management API endpoints, you MUST:**

1. **Write comprehensive tests** - Every endpoint requires full test coverage including:
   - Happy path scenarios for all HTTP methods
   - Error cases (404, 400, 422, 403, etc.)
   - Permission/authentication testing
   - Edge cases and validation scenarios

2. **Update API documentation** - All new endpoints must be documented with:
   - Request/response examples
   - Parameter descriptions
   - Error response formats
   - Authentication/permission requirements

3. **Review OAuth2 scopes and permissions** - Ensure appropriate scopes exist for:
   - Management API applications (`management_app:read`, `management_app:write`, etc.)
   - Personal Access Tokens
   - Different permission levels (admin vs user access)
   - Resource-specific scopes (`certificates:read`, `users:write`, etc.)

**API endpoints are not considered complete until all three requirements are satisfied.**

### API Documentation Locations

**OpenAPI Specification:**
- **Source File**: [lib/authify_web/controllers/api/docs_controller.ex](lib/authify_web/controllers/api/docs_controller.ex) (1975+ lines)
- **Runtime Spec Endpoint**: `GET /docs/openapi.json` (accessible at `http://localhost:4000/docs/openapi.json` in dev)
- **Runtime Interactive Endpoint**: `GET /docs/api` (accessible at `http://localhost:4000/docs/api` in dev)
- **Purpose**: Auto-generated OpenAPI 3.1.0 specification with deployment-specific URLs
- **Contains**: All Management API endpoints, schemas, parameters, authentication methods, and examples

**Human-Readable Documentation:**
- **README.md**: High-level overview, quick start guide, and common usage examples
- **Usage Examples**: Located in README under "Usage" section (lines 108-176)

**When updating the API:**
1. Add new endpoints to `docs_controller.ex` under the appropriate `build_*_paths()` function
2. Add new schemas to `build_schemas()` and create corresponding `build_*_schema()` functions
3. Update tags in `build_tags()` if adding a new resource category
4. Update README examples if the changes affect common use cases
