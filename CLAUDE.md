# Authify - Multi-tenant Identity Provider (Elixir/Phoenix Version)

A comprehensive, open-source, multi-tenant identity provider supporting both OAuth2/OIDC and SAML protocols. Built with Elixir and Phoenix 1.8.x.

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
- **Phoenix 1.8.x** - Web framework with LiveView
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

## Technical Notes

- **Use TDD instead of manual `curl` testing** - Tests reveal issues faster and provide better debugging information
- Use `mix phx.gen` generators to scaffold resources
- Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for commit messages
- **Template error handling** - Use `Keyword.get_values/2` for changeset errors, not direct key access
- **Mixed key consistency** - Keep string vs atom keys consistent in params throughout the pipeline
- **Virtual fields in tests** - Compare specific fields rather than full structs to avoid virtual field mismatches
- **DO NOT COMMIT FAILING TESTS** - Seriously, if tests are failing or the project fails to compile, we're not ready to commit. All tests and style checks must pass before using `git` to commit changes. Use `mix test` or occasionally `mix precommit` to confirm tests pass and style adherence.
- **Don't commit noisy tests** - Even if tests pass, if they produce unnecessary output (e.g., warnings, debug logs), they should be fixed before committing. Tests should be clean and only output relevant information when they fail. Passing tests shouldn't output debug logs, warnings, or other noise.
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
