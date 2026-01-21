<p align="center">
  <img src="priv/static/images/logo-readme.svg" alt="Authify Logo" width="400">
</p>

<p align="center"><strong>Multi-tenant Identity Provider with OIDC/OAuth 2.0, SAML 2.0, and SCIM 2.0</strong></p>

<p align="center">
  <a href="https://github.com/authify/authify/releases"><img src="https://img.shields.io/github/v/release/authify/authify?display_name=tag&sort=semver" alt="Latest Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT"></a>
  <a href="https://github.com/authify/authify/wiki"><img src="https://img.shields.io/badge/docs-wiki-blue" alt="Documentation"></a>
</p>

Authify is a self-hosted, open-source identity provider built with Elixir and Phoenix. It provides enterprise-grade authentication and authorization services with support for OAuth 2.0/OpenID Connect, SAML 2.0, and SCIM 2.0 protocols, offering both authentication flows and bi-directional user provisioning.

## ✨ Features

### **Identity Protocols**
- **OAuth 2.0 / OpenID Connect 1.0** - Full OIDC provider with authorization code flow
- **SAML 2.0 Identity Provider** - Complete SAML IdP with SSO and SLO support
- **SCIM 2.0 Provisioning** - Bi-directional user/group provisioning (Service Provider + Client)
- **Multi-protocol Support** - Use OIDC, SAML, and SCIM simultaneously

### **Multi-tenancy**
- **Organization-scoped** - Complete isolation between organizations
- **Per-org User Management** - Users, roles, and applications scoped to organizations
- **Flexible Domain Mapping** - Support for custom domains per organization

### **Management Capabilities**
- **Web Dashboard** - Intuitive admin interface for managing users and applications
- **REST API** - Comprehensive Management API with HATEOAS compliance
- **User Self-Service** - Profile management and password reset flows
- **Role-based Access Control** - Admin and user roles with proper authorization

### **Developer Experience**
- **OpenAPI 3.1.1 Specification** - Auto-generated, deployment-specific API docs
- **Header-based Versioning** - Clean API versioning without URL pollution
- **Comprehensive Test Coverage** - TDD approach with extensive test suites
- **Infrastructure as Code Ready** - Perfect for Terraform and automation tools

### **Email & Notifications**
- **User Invitations** - Email-based invitation system with secure tokens
- **Password Reset** - Self-service password reset via email
- **Email Verification** - Automatic verification for invited users, manual for direct creation
- **Organization-specific SMTP** - Configure SMTP per organization with encrypted credentials
- **Professional Templates** - HTML and plain text email templates for all notifications

### **SCIM 2.0 Provisioning (Bi-directional)**

**Service Provider (Inbound Provisioning):**
- **RFC 7644 Compliant** - Full SCIM 2.0 Service Provider implementation
- **Complete Resource Support** - Users and Groups with all CRUD operations
- **Advanced Filtering** - Rich query support with RFC 7644 filter expressions
- **Bulk Operations** - Efficient batch processing (up to 1000 operations)
- **ETag Support** - Optimistic concurrency control for conflict prevention
- **Self-Service Endpoint** - `/Me` endpoint for authenticated user operations
- **Discovery Endpoints** - ServiceProviderConfig, ResourceTypes, and Schemas
- **OAuth 2.0 Authentication** - Secure token-based access with granular scopes

**Current Limitations:**
- ⚠️ Search endpoint (`POST /.search`) not yet implemented (most clients use GET with filters)
- ⚠️ Schema extensions not supported (only core User/Group schemas)

**Client (Outbound Provisioning):**
- **Automatic Provisioning** - Push users and groups to downstream applications (Slack, GitHub, AWS, etc.)
- **Multi-provider Support** - Configure multiple SCIM targets per organization
- **Flexible Attribute Mapping** - Customize how user data maps to each provider
- **Sync Monitoring** - Track provisioning operations with detailed sync logs
- **Connection Testing** - Validate SCIM endpoint connectivity before going live
- **Manual Sync** - Trigger full synchronization of all users and groups
- **Retry Logic** - Automatic retry with exponential backoff for failed operations

### **Security & Compliance**
- **Multi-Factor Authentication (MFA)** - TOTP-based MFA with backup codes and trusted devices
- **Secure by Default** - Strong password policies and validation
- **Token Security** - Proper JWT handling with secure defaults
- **Rate Limiting** - Per-organization rate limits with hierarchical quotas and MFA lockout protection
- **Session Management** - Secure session handling with proper cleanup

## 🚀 Quick Start

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/authify/authify.git
   cd authify
   ```

2. **Install dependencies**
   ```bash
   mix deps.get
   npm install --prefix assets
   ```

3. **Configure database**
   ```bash
   vim config/dev.exs # setup your local MySQL credentials
   mix ecto.setup
   ```

4. **Start the development server**
   ```bash
   mix phx.server
   ```

5. **Complete initial setup**
   Visit [http://localhost:4000/setup](http://localhost:4000/setup) to create the first organization and admin user.

### Production Deployment

Pre-built container images are available from GitHub Container Registry:

```bash
docker run --rm -p 4000:4000 -p 9568:9568 \
  -e DATABASE_URL="ecto://user:pass@host/authify" \
  -e SECRET_KEY_BASE="$(mix phx.gen.secret)" \
  -e ENCRYPTION_PASSWORD="$(mix phx.gen.secret)" \
  -e PHX_HOST=auth.example.com \
  ghcr.io/authify/authify:latest
```

**For complete deployment options** including Docker Compose, Kubernetes manifests, scaling strategies, and operational best practices, see the **[Operations Guide](https://github.com/authify/authify/wiki/Operations)**.

## 📚 Documentation

- **[Getting Started](https://github.com/authify/authify/wiki/Getting-Started)** - Installation, setup, and quick testing guides
- **[Architecture](https://github.com/authify/authify/wiki/Architecture)** - Multi-tenant design, protocols, and system overview
- **[Management API](https://github.com/authify/authify/wiki/Management-API)** - Programmatic access, authentication, and scopes
- **[Operations](https://github.com/authify/authify/wiki/Operations)** - Production deployment, scaling, metrics, and troubleshooting
- **[Security](https://github.com/authify/authify/wiki/Security)** - Security features, hardening checklist, and best practices
- **[Roadmap](https://github.com/authify/authify/wiki/Roadmap)** - Completed features and planned initiatives
- **[Interactive API Docs](http://localhost:4000/docs)** - OpenAPI/Scalar UI (when running locally)

### Quick Examples

**OAuth 2.0 / OIDC:**
```bash
# Discovery endpoint
curl https://auth.yourcompany.com/your-org/.well-known/openid_configuration

# Authorization flow
https://auth.yourcompany.com/your-org/oauth/authorize?
  client_id=your_client_id&
  response_type=code&
  scope=openid profile email&
  redirect_uri=https://yourapp.com/callback
```

**SAML 2.0:**
```bash
# Get IdP metadata
curl https://auth.yourcompany.com/your-org/saml/metadata
```

**Management API:**
```bash
# Get access token
curl -X POST https://auth.yourcompany.com/your-org/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET"

# Use the API
curl -H "Authorization: Bearer YOUR_TOKEN" \
     https://auth.yourcompany.com/your-org/api/users
```

See the **[Getting Started](https://github.com/authify/authify/wiki/Getting-Started)** guide for detailed examples and testing instructions.

## 🧪 Development

### Running Tests

```bash
# Run the full test suite
mix test

# Run specific test files
mix test test/authify_web/controllers/api/

# Run previously failed tests
mix test --failed
```

### Code Quality

```bash
# Format code
mix format

# Run fast pre-commit checks (formatting, compilation, credo, sobelow)
mix precommit.fast

# Run full checks including tests
mix precommit
```

### Contributing

We welcome contributions! Please see our **[Contributing Guide](CONTRIBUTING.md)** for:
- Development workflow and branching strategy
- Testing standards and requirements
- Pull request guidelines
- Code style conventions

## 🔒 Security

### Reporting Security Issues

**IMPORTANT**: If you find a critical security vulnerability that could be actively exploited, please report it privately using GitHub's Security Advisories feature instead of creating a public issue:

1. Go to the [Security tab](https://github.com/authify/authify/security)
2. Click "Report a vulnerability"
3. Follow the private disclosure process

We take security seriously and will respond promptly to legitimate reports.

### Security Features

- Password security with bcrypt hashing and complexity requirements
- JWT token security with RS256 signing
- SAML assertions signed with RSA-SHA256
- Multi-tenant data isolation
- Per-organization rate limiting
- CSRF protection and security headers

For detailed security information, hardening checklists, and operational security guidance, see the **[Security Guide](https://github.com/authify/authify/wiki/Security)**.

## 🔌 Integrations

Authify works with any OAuth 2.0/OIDC or SAML 2.0 compatible application:

- **Terraform** - Use the Management API to manage resources as code
- **Grafana** - OIDC authentication for your monitoring dashboards
- **GitLab** - SAML SSO for your development teams
- **Slack** - OIDC for team authentication
- **Custom Applications** - Full OAuth 2.0 and SAML 2.0 support

Generate client libraries from the OpenAPI specification:

```bash
curl http://localhost:4000/docs/openapi.json > authify-openapi.json
openapi-generator generate -i authify-openapi.json -g python -o ./authify-python-client
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Support

- **Documentation** - [GitHub Wiki](https://github.com/authify/authify/wiki)
- **Issues** - [GitHub Issues](https://github.com/authify/authify/issues)
- **Discussions** - [GitHub Discussions](https://github.com/authify/authify/discussions)

## 🙏 Acknowledgments

Built with:
- **[Phoenix Framework](https://phoenixframework.org/)** - Web framework
- **[Elixir](https://elixir-lang.org/)** - Programming language
- **[Guardian](https://github.com/ueberauth/guardian)** - JWT authentication
- **[Ecto](https://hexdocs.pm/ecto/)** - Database wrapper and query generator
- **[Bootstrap](https://getbootstrap.com/)** - UI framework

Special thanks to:
- **[ExScim](https://github.com/ExScim/ex_scim)** - SCIM 2.0 filter parser implementation (adapted with security enhancements)

For complete acknowledgments and attribution details, see [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md).

---

**Authify** - Self-hosted identity provider for the modern web 🚀
