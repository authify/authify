<p align="center">
  <img src="priv/static/images/logo-readme.svg" alt="Authify Logo" width="400">
</p>

<p align="center"><strong>Multi-tenant OpenID Connect & SAML Identity Provider</strong></p>

<p align="center">
  <a href="https://github.com/authify/authify/releases"><img src="https://img.shields.io/github/v/release/authify/authify?display_name=tag&sort=semver" alt="Latest Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT"></a>
  <a href="https://github.com/authify/authify/wiki"><img src="https://img.shields.io/badge/docs-wiki-blue" alt="Documentation"></a>
</p>

Authify is a self-hosted, open-source identity provider built with Elixir and Phoenix. It provides enterprise-grade authentication and authorization services with support for OAuth 2.0/OpenID Connect and SAML 2.0 protocols.

## ✨ Features

### **Identity Protocols**
- **OAuth 2.0 / OpenID Connect 1.0** - Full OIDC provider with authorization code flow
- **SAML 2.0 Identity Provider** - Complete SAML IdP with SSO and SLO support
- **Multi-protocol Support** - Use both OIDC and SAML simultaneously

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

### **Security & Compliance**
- **Secure by Default** - Strong password policies and validation
- **Token Security** - Proper JWT handling with secure defaults
- **Rate Limiting** - Per-organization rate limits with hierarchical quotas
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
   cp config/dev.exs.example config/dev.exs
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

---

**Authify** - Self-hosted identity provider for the modern web 🚀
