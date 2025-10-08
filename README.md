<p align="center">
  <img src="priv/static/images/logo-dark.svg" alt="Authify Logo" width="400">
</p>

<h1 align="center">Authify</h1>

<p align="center"><strong>Multi-tenant OpenID Connect & SAML Identity Provider</strong></p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT"></a>
  <a href="#📖-documentation"><img src="https://img.shields.io/badge/OpenAPI-3.1.1-blue" alt="OpenAPI 3.1.1"></a>
</p>

Authify is a self-hosted, open-source identity provider built with Elixir and Phoenix. It provides enterprise-grade authentication and authorization services with support for OAuth 2.0/OpenID Connect and SAML 2.0 protocols.

## 🚀 Features

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
- **Audit Logging** - Track all authentication and authorization events
- **Session Management** - Secure session handling with proper cleanup

## 🏗️ Architecture

Authify is built as a **multi-tenant identity provider** that can serve multiple organizations from a single deployment:

```
┌─────────────────────────────────────────────────────────────┐
│                        Authify                              │
├─────────────────────────────────────────────────────────────┤
│  Organization A          │  Organization B                  │
│  ├─ Users                │  ├─ Users                        │
│  ├─ OAuth Apps           │  ├─ OAuth Apps                   │
│  ├─ SAML Providers       │  ├─ SAML Providers               │
│  └─ Settings             │  └─ Settings                     │
├─────────────────────────────────────────────────────────────┤
│                   Management API                            │
│  ├─ Organization API     │  ├─ Authentication               │
│  ├─ Users API            │  ├─ OpenAPI Docs                │
│  └─ Applications API     │  └─ HATEOAS Navigation          │
├─────────────────────────────────────────────────────────────┤
│              Identity Protocol Endpoints                    │
│  ├─ OIDC (/:org_slug/.well-known/openid_configuration)    │
│  ├─ OAuth 2.0 (/:org_slug/oauth/authorize, /token)        │
│  └─ SAML 2.0 (/:org_slug/saml/sso, /metadata)             │
└─────────────────────────────────────────────────────────────┘
```

## 🛠️ Installation & Setup

### Prerequisites

- **Elixir** 1.14+ with OTP 25+
- **Phoenix** 1.8.1
- **MySQL** 8.0+ (or compatible MariaDB)
- **Node.js** 18+ (for frontend assets)

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/authify.git
   cd authify
   ```

2. **Install dependencies**
   ```bash
   mix deps.get
   npm install --prefix assets
   ```

3. **Configure database**
   ```bash
   # Copy and edit the configuration
   cp config/dev.exs.example config/dev.exs

   # Create and migrate database
   mix ecto.setup
   ```

4. **Start the development server**
   ```bash
   mix phx.server
   ```

5. **Complete initial setup**

   Visit [http://localhost:4000/setup](http://localhost:4000/setup) to create the first organization and admin user.

### Production Deployment

Below are condensed deployment options. Detailed, living documentation will move to the wiki.

#### 1. Docker (Production Image)

Build and run directly (multi-stage Dockerfile provided):

```bash
docker build -t authify:latest .
docker run --rm -p 4000:4000 -p 9568:9568 \
  -e DATABASE_URL="ecto://user:pass@host/authify" \
  -e SECRET_KEY_BASE="$(mix phx.gen.secret)" \
  -e ENCRYPTION_PASSWORD="$(mix phx.gen.secret)" \
  -e PHX_HOST=auth.example.com \
  authify:latest
```

#### 2. Docker Compose (App + MySQL + Optional Metrics Stack)

The provided `docker-compose.yml` includes MySQL plus optional Prometheus/Grafana profiles.

```bash
docker compose up -d db
docker compose up -d authify
# (optional) docker compose --profile monitoring up -d prometheus grafana
```

First-time run executes migrations automatically. Visit `http://localhost:4000/setup`.

#### 3. Kubernetes (Reference Manifests)

Reference manifests under `k8s/` (deployment, service, ingress, HPA, service monitor, namespace). Apply in order:

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml        # contains DB creds, SECRET_KEY_BASE, ENCRYPTION_PASSWORD
kubectl apply -f k8s/mysql-statefulset.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/ingress.yaml
kubectl apply -f k8s/hpa.yaml
kubectl apply -f k8s/servicemonitor.yaml   # if using Prometheus Operator
```

Key production considerations:
- Set strong `SECRET_KEY_BASE` and `ENCRYPTION_PASSWORD` (do not reuse) in secrets
- Externalize MySQL (managed offering) for HA & automated backups
- Configure TLS at ingress (Let’s Encrypt or managed certs)
- Restrict `/metrics` exposure (network policies / auth when needed)
- Tune DB `POOL_SIZE` based on replica count (`POOL_SIZE * replicas <= DB max_connections * safety_margin`)
- Configure organization domain + base tenant domain after bootstrap (global settings)

#### 4. Zero-Downtime Upgrades

1. Build & push new image
2. Apply migrations out-of-band (Kubernetes job or one-off task):
   ```bash
   kubectl run migrate --image=ghcr.io/your-org/authify:<tag> --restart=OnFailure \
     --env-from=secret/authify-secrets -- bin/authify eval 'Authify.Release.migrate'
   ```
3. Roll deployment (Kubernetes rolling update or compose re-deploy)

#### 5. Backup & Recovery (Interim Guidance)

Until automated tooling lands:
- Daily logical dumps: `mysqldump --single-transaction authify > backup.sql`
- Retain SAML certificates & configuration exports (API) separately
- Verify restore quarterly (disaster game day)

#### 6. Observability Quick Start
- Prometheus scrapes metrics on `:9568/metrics`
- Grafana: import latency & error rate starter dashboards; alert on p95 > target, 5xx surge, auth failure spikes

#### 7. Scaling Guidelines
| Layer | Strategy |
|-------|----------|
| Web Nodes | Horizontal (stateless) |
| Database | Increase IOPS / CPU; connection pool tuning |
| Rate Limits | ETS local with PubSub invalidation (add nodes freely) |
| Metrics | Externalize Prometheus + long-term storage (e.g. Thanos) |

More deployment patterns (Terraform modules, multi-region) are on the roadmap.

## 📚 Usage

### Organization Signup

1. Visit your Authify instance (e.g., `https://auth.yourcompany.com/signup`)
2. Create your organization with an admin account
3. Configure your organization settings and branding
4. Start creating OAuth applications and SAML providers

### OAuth 2.0 / OpenID Connect

```bash
# Discovery endpoint
curl https://auth.yourcompany.com/your-org/.well-known/openid_configuration

# Authorization endpoint
https://auth.yourcompany.com/your-org/oauth/authorize?
  client_id=your_client_id&
  response_type=code&
  scope=openid profile email&
  redirect_uri=https://yourapp.com/callback

# Token endpoint
curl -X POST https://auth.yourcompany.com/your-org/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=...&client_id=...&client_secret=..."
```

### SAML 2.0

```bash
# Metadata endpoint
curl https://auth.yourcompany.com/your-org/saml/metadata

# SSO endpoint (POST binding)
https://auth.yourcompany.com/your-org/saml/sso

# Single Logout
https://auth.yourcompany.com/your-org/saml/slo
```

### Management API

The Management API provides programmatic access to all Authify functionality using OAuth2 client credentials.

#### Getting Started

1. **Create a Management API Application** in your organization settings
2. **Select scopes** for the permissions you need (e.g., `users:read`, `applications:write`)
3. **Save the `client_id` and `client_secret`** (the secret is only shown once!)

#### Authentication Flow

Management API apps use the **OAuth2 Client Credentials** grant type:

```bash
# Step 1: Exchange client credentials for an access token
curl -X POST https://auth.yourcompany.com/your-org/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "scope=users:read applications:write"  # Optional: omit to use all granted scopes

# Response:
# {
#   "access_token": "eyJhbGc...",
#   "token_type": "Bearer",
#   "expires_in": 3600,
#   "scope": "users:read applications:write"
# }

# Note: The 'scope' parameter is optional. If omitted, the token will have all scopes
# granted to your Management API app. Include 'scope' to request a subset for least privilege.
```

#### Using the Access Token

```bash
# Step 2: Use the access token to call Management API endpoints
# Note: Accept header can be "application/json" (defaults to latest version)
# or "application/vnd.authify.v1+json" for explicit versioning

# List users
curl -H "Accept: application/vnd.authify.v1+json" \
     -H "Authorization: Bearer eyJhbGc..." \
     https://auth.yourcompany.com/your-org/api/users

# Create OAuth application
curl -X POST https://auth.yourcompany.com/your-org/api/applications \
  -H "Accept: application/vnd.authify.v1+json" \
  -H "Authorization: Bearer eyJhbGc..." \
  -H "Content-Type: application/json" \
  -d '{
    "application": {
      "name": "My App",
      "redirect_uris": "https://myapp.com/callback",
      "scopes": "openid profile email"
    }
  }'

# Invite a user
curl -X POST https://auth.yourcompany.com/your-org/api/invitations \
  -H "Accept: application/vnd.authify.v1+json" \
  -H "Authorization: Bearer eyJhbGc..." \
  -H "Content-Type: application/json" \
  -d '{
    "invitation": {
      "email": "user@example.com",
      "role": "user"
    }
  }'
```

#### Available Scopes

Management API scopes control what actions your application can perform:

| Scope | Description |
|-------|-------------|
| `users:read` | Read user information |
| `users:write` | Create, update, delete users |
| `invitations:read` | Read invitations |
| `invitations:write` | Create, update, delete invitations |
| `applications:read` | Read OAuth applications |
| `applications:write` | Create, update, delete OAuth applications |
| `application_groups:read` | Read application groups |
| `application_groups:write` | Manage application groups |
| `saml:read` | Read SAML service providers |
| `saml:write` | Manage SAML service providers |
| `certificates:read` | Read IdP certificates |
| `certificates:write` | Manage IdP certificates |
| `organizations:read` | Read organization settings |
| `organizations:write` | Update organization settings |
| `management_app:read` | Read Management API apps |
| `management_app:write` | Manage Management API apps |

#### API Documentation

```bash
# Get full OpenAPI specification
curl https://auth.yourcompany.com/docs/openapi.json

# Interactive API documentation (Swagger UI)
# Visit: https://auth.yourcompany.com/docs/api
```

#### Using Personal Access Tokens

Alternatively, users can create Personal Access Tokens from their profile:

```bash
# Use a PAT instead of client credentials
curl -H "Authorization: Bearer authify_pat_..." \
     -H "Accept: application/json" \
     https://auth.yourcompany.com/your-org/api/users
```

PATs are useful for:
- Development and testing
- User-specific automation scripts
- CI/CD pipelines with user context

## 🔧 Configuration

### Environment Variables

Key configuration options:

```bash
# Database
DATABASE_URL=mysql://user:password@localhost/authify

# Application
SECRET_KEY_BASE=your_secret_key
PHX_HOST=auth.yourcompany.com
PORT=4000

# Metrics & Observability
ENABLE_METRICS=true  # Set to false to disable Prometheus metrics (default: true)
```

**Note:** Email configuration is done per-organization via the web dashboard or Management API. See the [Email Configuration](#email-configuration) section for details.

### Configuration Reference (Summary)

| Area | Key / Setting | Environment Variable | Description | Default |
|------|---------------|----------------------|-------------|---------|
| Core | Secret Key Base | `SECRET_KEY_BASE` | Cryptographic signing/encryption base | (required in prod) |
| Core | Encryption Password | `ENCRYPTION_PASSWORD` | Encrypts stored sensitive fields (fallbacks to `SECRET_KEY_BASE`) | dev fallback |
| Core | Hostname | `PHX_HOST` | External host used in URLs | example.com |
| Core | Port | `PORT` | HTTP port | 4000 |
| DB | Database URL | `DATABASE_URL` | Ecto connection string | (required in prod) |
| DB | Pool Size | `POOL_SIZE` | DB connection pool size | 10 |
| Metrics | Enable Metrics | `ENABLE_METRICS` | Enable Prometheus exporter (port 9568) | true |
| Cluster | Release Name | `RELEASE_NAME` | Enables k8s DNS clustering | unset |
| Cluster | Release Namespace | `RELEASE_NAMESPACE` | Namespace for clustering | unset |
| Cluster | DNS Query | `DNS_CLUSTER_QUERY` | Custom DNS SRV name | unset |
| TLS | Force SSL | (config) | Use endpoint force_ssl option | disabled |
| Rate Limits | Per-scope limits | (UI / API) | auth/oauth/saml/api org-specific limits | quota defaults |
| Rate Limits | Quotas | (Super admin UI / API) | Upper bounds for org limits | schema defaults |
| Feature Flags | OAuth Enabled | (UI / API) | Toggle OAuth flows | on |
| Feature Flags | SAML Enabled | (UI / API) | Toggle SAML flows | on |
| Feature Flags | Invitations Enabled | (UI / API) | Toggle user invitation system | on |
| SMTP | Org SMTP Settings | (UI / API) | Per-org mail delivery configuration | unset per org |

See `ROADMAP.md` for upcoming configuration additions.

### Metrics & Observability

Authify exposes Prometheus-compatible metrics on port **9568** at `/metrics` by default. These metrics include:

- **HTTP Request Metrics** - Request counts, latency histograms, and error rates (tagged by organization, route, method, status)
- **Database Metrics** - Query performance, connection pool stats
- **VM Metrics** - Memory usage, process counts, scheduler info
- **Business Metrics** - OAuth flows, SAML authentications, user logins

**Example metrics queries:**

```bash
# Fetch all metrics
curl http://localhost:9568/metrics

# Filter by organization in Prometheus/Grafana
rate(phoenix_endpoint_stop_duration_count{organization="acme-corp"}[5m])

# 95th percentile latency per organization
histogram_quantile(0.95, rate(phoenix_endpoint_stop_duration_bucket[5m]))
```

**Disable metrics to save resources:**

```bash
# Start Authify with metrics disabled
ENABLE_METRICS=false mix phx.server
```

Disabling metrics saves memory and CPU resources if you don't need observability. Metrics are always disabled during test runs.

### Rate Limiting

Authify provides hierarchical, per-organization rate limiting to prevent abuse and noisy neighbor problems:

- Scopes: `auth` (login & password flows), `oauth` (authorization & token), `saml` (SSO/SLO), `api` (Management API)
- Each scope has a QUOTA (upper bound, settable only by super admins) and an optional org-specific LIMIT (set by org admins). If no org limit is set, the quota applies directly.
- Current implementation uses a fixed 60 second window per scope via an ETS-backed counter strategy (Hammer). Future roadmap includes burst + sustained windows and richer headers.

Configuration:
- UI: `/:org_slug/settings/configuration` → Rate Limits section
- Quotas (super admin only): `authify-global/settings/configuration`
- API: Update organization configuration resource (same payload as other settings)

Behavior:
- When exceeded, requests are rejected (HTTP 429) with a JSON error body for API requests or an appropriate user-facing error for interactive flows.
- Rate limit values are cached in-memory for performance and updated immediately on change.

Planned enhancements (see ROADMAP): headers `X-RateLimit-Limit`, `X-RateLimit-Remaining`, structured metrics, and burst windows.

### Email Configuration

Authify supports organization-specific SMTP configuration for sending emails:

**Development Mode:**
- Emails are captured in the local mailbox at `http://localhost:4000/dev/mailbox`
- No SMTP configuration required for testing
- Uses `tenant_base_domain` for email links (e.g., `http://test-org.authify.local:4000`)

**Production Mode:**
- Configure SMTP per organization via the web dashboard or API
- SMTP credentials are encrypted at rest
- Email links use configured `email_link_domain` or fall back to `tenant_base_domain`

**Email Types:**
- **Invitation Emails** - Sent when admins invite new users (with auto-verify on acceptance)
- **Password Reset** - Self-service password reset with secure, expiring tokens (24h)
- **Email Verification** - Sent to directly-created users (24h expiry, resend available)

**Configuring SMTP for an Organization:**

Via Web Dashboard:
1. Navigate to `/:org_slug/settings/configuration`
2. Scroll to "Email Settings"
3. Configure SMTP server, port, credentials, and from address
4. Set `email_link_domain` for email links (e.g., `auth.yourcompany.com`)

Via Management API:
```bash
curl -X PUT https://auth.yourcompany.com/your-org/api/organization/configuration \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "configuration": {
      "smtp_server": "smtp.mailgun.org",
      "smtp_port": 587,
      "smtp_username": "postmaster@mg.yourcompany.com",
      "smtp_password": "your-smtp-password",
      "smtp_from_email": "noreply@yourcompany.com",
      "smtp_from_name": "Your Company Auth",
      "email_link_domain": "auth.yourcompany.com"
    }
  }'
```

### Multi-tenant Configuration

Each organization can be configured independently:

- **Custom domains** - Point `auth.client.com` to your Authify instance
- **Branding** - Logo, colors, and organization name
- **SAML providers** - Configure multiple SAML service providers
- **OAuth applications** - Each org manages their own OAuth apps
- **Email settings** - Per-organization SMTP configuration with encrypted credentials
- **Feature toggles** - Enable/disable OAuth, SAML, and invitations per organization

### Global Settings

System administrators can configure global settings via the authify-global organization:

- **Organization Registration** - Control whether new organizations can self-register
- **Site Branding** - Set the site name and support email for the entire instance
- **Access via UI** - Navigate to `/authify-global/settings/configuration`
- **Access via API** - `GET/PUT /authify-global/api/organization/configuration`

## 🔌 Integrations

### Popular Integrations

- **Terraform** - Use the Management API to manage resources as code
- **Grafana** - OIDC authentication for your monitoring dashboards
- **GitLab** - SAML SSO for your development teams
- **Slack** - OIDC for team authentication
- **Custom Applications** - Full OAuth 2.0 and SAML 2.0 support

### Client Libraries

Generate client libraries from our OpenAPI specification:

```bash
# Download the spec
curl https://auth.yourcompany.com/docs/openapi.json > authify-openapi.json

# Generate clients with openapi-generator
openapi-generator generate -i authify-openapi.json -g python -o ./authify-python-client
openapi-generator generate -i authify-openapi.json -g typescript-axios -o ./authify-ts-client
```

## 🧪 Development

### Running Tests

```bash
# Run the full test suite
mix test

# Run specific test files
mix test test/authify_web/controllers/api/
mix test test/authify/accounts_test.exs

# Run tests with coverage
mix test --cover
```

### API Development

```bash
# Format code
mix format

# Type checking (if using Dialyzer)
mix dialyzer

# Security analysis
mix sobelow
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for your changes
4. Ensure all tests pass (`mix test`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📖 Documentation

### API Documentation

**Interactive Documentation (Scalar UI)**

Browse the API interactively with a modern, searchable interface:

```
Development:  http://localhost:4000/docs
Production:   https://auth.yourcompany.com/docs
```

The interactive docs provide:
- Try-it-out functionality to test endpoints
- Code examples in multiple languages
- Search and filtering
- Beautiful, modern UI

**OpenAPI Specification (Auto-Generated)**

The Management API is fully documented with an OpenAPI 3.1.1 specification that's auto-generated from the source code:

```bash
# Development
curl http://localhost:4000/docs/openapi.json

# Production
curl https://auth.yourcompany.com/docs/openapi.json
```

The OpenAPI specification includes:
- All Management API endpoints (Organizations, Users, Applications, Certificates, Application Groups, Invitations)
- Complete request/response schemas
- Authentication requirements (API keys, session auth)
- Parameter descriptions and examples
- Error response formats
- HATEOAS navigation links

**Source Code**: The specification is generated by [lib/authify_web/controllers/api/docs_controller.ex](lib/authify_web/controllers/api/docs_controller.ex)

**Generate Client Libraries:**

```bash
# Download the spec
curl http://localhost:4000/docs/openapi.json > authify-openapi.json

# Generate clients with openapi-generator
openapi-generator generate -i authify-openapi.json -g python -o ./authify-python-client
openapi-generator generate -i authify-openapi.json -g typescript-axios -o ./authify-ts-client
openapi-generator generate -i authify-openapi.json -g go -o ./authify-go-client
```

### Additional Documentation

- **[Deployment Guides](docs/deployment/)** - Production deployment instructions
- **[Integration Examples](docs/integrations/)** - Common integration patterns
- **[Development Setup](docs/development.md)** - Local development environment

## 🔒 Security

### Reporting Security Issues

Please report security vulnerabilities to [security@yourcompany.com](mailto:security@yourcompany.com). Do not create public GitHub issues for security vulnerabilities.

### Security Features

- **Password Security** - Bcrypt hashing with complexity requirements
- **Token Security** - Secure JWT generation and validation
- **Session Security** - Secure session management with proper cleanup
- **Input Validation** - Comprehensive input validation and sanitization
- **Rate Limiting** - Protection against brute force attacks

### Security Hardening Checklist

| Category | Recommendation |
|----------|---------------|
| TLS | Terminate HTTPS at ingress / LB; enable HSTS (force_ssl) |
| Secrets | Store `SECRET_KEY_BASE` & `ENCRYPTION_PASSWORD` in a secret manager |
| DB | Enforce least privilege DB user; enable backups & binlogs |
| Metrics | Restrict `/metrics` endpoint to internal network / scrape targets |
| Headers | Validate CSP / strict transport / X-Frame-Options (via endpoint config) |
| SAML | Rotate signing certs periodically (documented procedure TBD) |
| OAuth | Monitor token issuance volume & anomalous scope escalation |
| Session | Set secure cookies behind TLS; review idle/absolute timeout policies (future roadmap) |
| Rate Limits | Tune quotas for production traffic profile |
| Logging | Add structured audit logging before enabling broad external use (roadmap) |

### Operational Guide (Overview)

| Aspect | Notes |
|--------|-------|
| Stateless App | Scale horizontally (each node uses DB + clustering for coordination) |
| Clustering | Optional Kubernetes DNS strategy (`RELEASE_NAME` / `RELEASE_NAMESPACE`) |
| Health | Standard Phoenix endpoint responds 200; add custom health probe if needed |
| Metrics | Prometheus text format on :9568 `/metrics` |
| Scaling | Ensure DB pool scaled with replicas (`POOL_SIZE * replicas <= DB max`) |
| Rate Limits | Stored in DB; cached in memory; publish/subscribe invalidation via PubSub |
| Backups | Implement MySQL backup automation externally (scripts / operator) |
| Certificate Rotation | Generate new cert, activate, then distribute metadata (SAML SPs) |

### Troubleshooting (Quick Reference)

| Symptom | Possible Cause | Action |
|---------|----------------|--------|
| 401 on token exchange | Invalid client secret or scope not granted | Verify app config & scopes |
| 400 invalid_redirect_uri | Redirect URI mismatch | Add exact redirect URI to app config |
| SAML "Unknown service provider" | EntityID mismatch | Confirm SP metadata entityID matches configured value |
| SAML clock skew errors | Host time drift | Sync NTP / confirm system clock |
| Frequent 429 errors | Too low rate limit | Adjust org limit or increase quota (super admin) |
| Metrics missing | ENABLE_METRICS=false or blocked network | Check env var and network policy |
| Login redirect loop | Cookies blocked / secret mismatch | Verify domain, `SECRET_KEY_BASE`, cookie settings |

---

## 📌 Roadmap & Status

For strategic initiatives (MFA, Audit Logging, SCIM, SAML encryption) see: [`ROADMAP.md`](ROADMAP.md).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Support

- **Documentation** - [https://github.com/authify/authify/wiki](https://github.com/authify/authify/wiki)
- **Issues** - [GitHub Issues](https://github.com/authify/authify/issues)
- **Discussions** - [GitHub Discussions](https://github.com/authify/authify/discussions)
- **Community** - Discord Server coming soon!

## 🙏 Acknowledgments

Built with:
- **[Phoenix Framework](https://phoenixframework.org/)** - Web framework
- **[Elixir](https://elixir-lang.org/)** - Programming language
- **[Guardian](https://github.com/ueberauth/guardian)** - JWT authentication
- **[Ecto](https://hexdocs.pm/ecto/)** - Database wrapper and query generator
- **[Bootstrap](https://getbootstrap.com/)** - UI framework

---

**Authify** - Self-hosted identity provider for the modern web 🚀
