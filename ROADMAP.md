# Authify Roadmap

A consolidated view of completed, in‑progress, and planned features. This file will eventually migrate to the project wiki. Dates are indicative; priorities may adjust based on community feedback and security considerations.

## Guiding Principles
- Security and tenant isolation are non‑negotiable
- Standards compliance (OAuth2/OIDC, SAML 2.0) over proprietary shortcuts
- Operational clarity: observability, rate limiting, and safe defaults
- Extensibility without fragmentation

## ✅ Completed (Highlights)

### Core Platform
- Multi‑tenant architecture with org‑scoped isolation
- Organization signup & bootstrap admin flow
- Organization + global configuration system (feature toggles, SMTP, domains)
- User management, roles (admin, user, global admin), username support
- Invitation system (email-based onboarding)
- Password policies & reset flows (secure tokens, 24h expiry)
- Email verification for directly created users
- Extended user profile fields (avatar, locale, timezone, phone, website, team, title)
- Application Groups with per-user visibility scoping
- Groups (OIDC claims, SAML attributes, Management API)

### Protocols
- OAuth2 Authorization Code with OIDC (discovery, JWKS, userinfo, consent)
- OAuth2 persistent user consent tracking
- OAuth 2.1 strict compliance mode (per-org, PKCE enforcement)
- SAML 2.0 IdP with metadata, SSO (Redirect + POST), assertions, attribute mapping
- SAML attribute template interpolation (mustache-style)
- SAML Single Logout (SP + IdP initiated, multi-session coordination)
- JWT issuance (access + ID tokens) with RS256 signing

### MFA
- TOTP app-based MFA with backup codes
- WebAuthn / FIDO2 hardware key and passkey support
- MFA rate limiting and lockout protection
- Organization-level MFA enforcement policies
- Admin MFA management UI and Management API endpoints

### Provisioning & Integration
- SCIM 2.0 bi-directional provisioning (users + groups lifecycle)

### Administration & UI
- Bootstrap 5 responsive dashboard (users, apps, SAML providers, certificates, groups)
- Rate limiting configuration UI (per org)
- Comprehensive audit logging system (authentication, authorization, configuration, security events)
- Task engine (Oban-based) with scheduling, telemetry, LiveView UI, and Management API
- User profile UI with OAuth consent management

### Security & Configuration
- Configurable per‑organization feature toggles (OAuth2, SAML, invitations)
- IdP certificate management (self-signed generation & activation)
- Prometheus metrics (HTTP, DB, VM, business metrics)
- Security headers & CSRF protections

### Infrastructure & Delivery
- Dockerfile (multi-stage) & docker-compose for dev
- Kubernetes manifests (deployments, ingress, HPA, service monitor)
- libcluster integration for distributed nodes
- OpenAPI 3.1 spec generation & interactive docs
- Comprehensive test suites for OAuth, SAML, SCIM, multi-tenant isolation

## 🔄 In Progress
(Currently none – pipeline is clear for next strategic features.)

## 🚧 Production-Readiness Blockers
These items represent the threshold between early-stage and production-ready. The project is not yet recommended for production use until these are addressed.

1. **Test Suite Performance & Isolation**
   - Parallel execution, async configuration, faster CI times
   - Reduce friction of adding new tests as the codebase grows
2. **Protocol Integration Test Harness**
   - Built-in OAuth2 client, SAML SP, and SCIM consumer fixtures
   - Exercise full IdP flows (authorization code dance, SSO, provisioning lifecycle) in tests without external applications
3. **Key Rotation Scheduling**
   - Automated/scheduled rotation for JWT signing and SAML certificates
   - Currently requires manual intervention
4. **Session Management**
   - Centralized session revocation dashboard
   - Idle + absolute session lifetime policies per org
5. **SAML Assertion Encryption** (optional feature)
   - Configurable per SP; signing-only is the current baseline
6. **Backup & Recovery**
   - Documented MySQL dump/restore patterns and key material handling
   - Helper `mix` tasks for common backup/restore operations

## 🎯 Near-Term (High Priority)

1. **Audit Log Export**
   - Export interfaces for the existing audit logging system
   - Stdout JSON streaming, webhook delivery, and/or file export
2. **Token Introspection Endpoint** (RFC 7662)
   - Allows resource servers to validate tokens without trusting clients
   - Critical for production service-to-service integrations
3. **OIDC Logout**
   - Front-channel and/or back-channel logout support
   - Proper session termination when users log out of OIDC relying parties
4. **Hardened Rate Limiting**
   - Burst + sustained windows, clearer response headers, admin observability page, metrics for rate limit hits and lockouts, and Management API endpoints for configuration and monitoring
5. **Personal Access Token Enhancements**
   - Fine-grained scope editing and rotation policies

## 🗺️ Mid-Term (Strategic, not in any particular order)

1. **Dynamic Client Registration** (OIDC RFC 7591)
2. **Device Authorization Grant** (OAuth2 device flow, RFC 8628)
   - Support for CLI tools and IoT/headless clients
3. **Token Revocation Endpoint** (RFC 7009)
   - Allows clients to explicitly invalidate access and refresh tokens
4. **Identity Federation / Upstream IdP**
   - Allow Authify to act as a relying party to an upstream OIDC or SAML provider
   - Enables enterprise SSO chaining and social login foundations
5. **Passkey-only / Passwordless Flows**
   - Beyond WebAuthn as MFA; full passwordless authentication as a first-class option
6. **SAML Advanced Features**
   - RequestedAuthnContext handling
   - Attribute consuming services
   - NameID format policies and encryption key rotation UX
7. **External KMS Integration** (optional)
   - Vault or cloud KMS backend for JWT signing and SAML key material

## 🔬 Exploratory / Long-Term

- **LDAP / Active Directory Integration** — sync or on-demand identity federation to internal directory
- **MFA SMS/Email Fallback** — optional; risk tradeoffs to be documented
- **Self-Service Social Login Providers** — allow orgs to configure upstream providers (Google, GitHub, etc.) per org
- **Pluggable Policy Engine** — OPA/Rego or Cedar-style authorization rules
- **Delegated Administration** — sub-org / hierarchical tenancy model
- **Feature Usage Analytics Export**
- **Multi-Region Replication Strategy**

## 📘 Documentation Expansion
- Security hardening guide (TLS termination, headers, secrets rotation, metrics exposure)
- Operational playbooks (scaling, alerting, incident triage)
- Troubleshooting catalog (clock skew, invalid redirect URI, SAML clock drift, rate limit hits)
- Client integration guides (Grafana, GitLab, Terraform module examples)

## 🧩 Developer Experience Improvements
- Improved local bootstrap script (seed org + admin + sample app/SP)
- Live dashboard for background jobs (task engine UI already in place; expand coverage)

## ⚠️ Known Gaps / Not Yet Implemented
These are intentionally pending and should not be assumed present in production deployments today:

- Test suite performance and integration test harness
- Key rotation scheduling (manual only)
- Session lifetime policies and centralized revocation
- SAML assertion/response encryption (signing only currently supported)
- Automated backups / restore tooling
- Audit log export / streaming
- Token introspection (RFC 7662)
- OIDC logout (front/back-channel)
- Dynamic client registration
- Device authorization grant (device flow)
- Passkey-only / passwordless flows
- Identity federation to upstream IdPs
- Pluggable policy engine
- LDAP/AD integration

## ❗ Breaking Change Policy
- Management API changes that remove or rename fields require a version bump (Accept header negotiation)
- Additive, non-breaking fields allowed without version increment (documented in OpenAPI spec)
- Deprecations must appear in spec with `deprecated: true` for one minor cycle before removal

## 🔐 Security Roadmap Snapshot
| Area | Current | Planned Next | Future |
|------|---------|--------------|--------|
| Token Issuance | JWT RS256 | Key rotation scheduling | External KMS |
| MFA | TOTP + WebAuthn/FIDO2 | Passwordless flows | SMS/Email fallback (opt-in) |
| SAML | Signing + SLO | Encryption opt-in | Advanced bindings / policy |
| Logging | Structured audit log (internal) | Export / streaming | Event-driven integrations |
| Provisioning | SCIM 2.0 (users/groups) | Identity federation | LDAP/AD sync |
| Sessions | Per-request auth | Lifetime policies + revocation dashboard | Multi-region session store |

## ✅ Definition of Done (Feature Level)
A feature is only "Done" when:
1. Code implemented & formatted
2. Tests (happy path + edge + isolation) added & passing
3. No compiler warnings
4. OpenAPI spec updated (if API-related)
5. README / docs updated for user-visible impact
6. Roadmap updated if it moves an item's status

## 🛡️ Contribution Guardrails
- No feature merges that degrade tenant isolation
- No silent security-impacting changes (must be documented)
- Favor explicit configuration over hidden defaults

## 📩 Feedback & Prioritization
Open issues with the `feature-request` label or start a discussion thread. High-signal production use cases and security improvements are prioritized over cosmetic UI changes.

---
Last updated: 2026-04-01