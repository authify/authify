# Authify Roadmap

A consolidated view of completed, in‑progress, and planned features. This file will eventually migrate to the project wiki. Dates are indicative; priorities may adjust based on community feedback and security considerations.

## Guiding Principles
- Security and tenant isolation are non‑negotiable
- Standards compliance (OAuth2/OIDC, SAML 2.0) over proprietary shortcuts
- Operational clarity: observability, rate limiting, and safe defaults
- Extensibility without fragmentation

## ✅ Completed (Highlights)
(Extracted from internal status documents; trimmed to major pillars.)

### Core Platform
- Multi‑tenant architecture with org‑scoped isolation
- Organization signup & bootstrap admin flow
- Organization + global configuration system (feature toggles, SMTP, domains)
- User management, roles (admin, user, global admin)
- Invitation system (email-based onboarding)
- Password policies & reset flows (secure tokens, 24h expiry)
- Email verification for directly created users

### Protocols
- OAuth2 Authorization Code with OIDC (discovery, JWKS, userinfo, consent)
- SAML 2.0 IdP with metadata, SSO (Redirect + POST), assertions, attribute mapping
- SAML Single Logout (SP + IdP initiated, multi-session coordination)
- JWT issuance (access + ID tokens) with Guardian

### Administration & UI
- Bootstrap 5 responsive dashboard (users, apps, SAML providers, certificates, groups)
- Application Groups with per-user visibility scoping
- Rate limiting configuration UI (per org)

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
- Comprehensive test suites for OAuth, SAML, multi-tenant isolation

## 🔄 In Progress
(Currently none – pipeline is clear for next strategic features.)

## 🎯 Near-Term (High Priority)
1. Audit Logging & Event Stream
   - Structured, immutable log of authentication, authorization, configuration, and security events
   - Export interfaces (stdout JSON, optional webhook / future streaming)
2. MFA (Phase 1: TOTP app-based)
   - Per-user MFA enrollment & backup codes
   - Enforcement policy (mandatory vs optional per org)
3. SAML Assertion/Response Encryption (optional feature)
   - Configurable per SP; maintain signing as default baseline
4. Backup & Recovery Guidelines (Documentation + helper mix task)
   - MySQL dump/restore patterns, key material handling
5. Hardened Rate Limiting Extensions
   - Burst + sustained windows, clearer headers, admin observability page

## 🗺️ Mid-Term (Strategic, not in any particular order)
1. LDAP / Active Directory Integration
   - Sync or on-demand identity federation to internal directory
2. MFA (Phase 2 & 3)
   - WebAuthn / FIDO2 support
   - SMS / Email fallback (optional; risk tradeoffs documented)
3. Personal Access Token Enhancements
   - Fine-grained scope editing & rotation policies
4. Dynamic Client Registration (OIDC)
5. SCIM 2.0 Provisioning API
   - User + group lifecycle management
6. SAML Advanced Features
   - Attribute consuming services
   - RequestedAuthnContext handling
   - NameID format policies & encryption key rotation UX
7. Session Management Enhancements
   - Centralized session revocation dashboard
   - Idle + absolute session lifetime policies per org
8. Secrets & Key Management
   - Key rotation scheduling for JWT & SAML certs
   - External KMS integration (optional)

## 🔬 Exploratory / Research
- Pluggable policy engine (e.g., OPA/Rego or Cedar-style authorization rules)
- Delegated administration model (sub-org / hierarchical tenancy)
- Feature usage analytics export
- Multi-region replication strategy

## 📘 Documentation Expansion
- Security hardening guide (TLS termination, headers, secrets rotation, metrics exposure)
- Operational playbooks (scaling, alerting, incident triage)
- Troubleshooting catalog (clock skew, invalid redirect URI, SAML clock drift, rate limit hits)
- Client integration guides (Grafana, GitLab, Terraform module examples)

## 🧩 Developer Experience Improvements
- Improved local bootstrap script (seed org + admin + sample app/SP)
- Live dashboard for background jobs once job system lands
- Optional Oban integration for retries, token cleanup automation

## ⚠️ Known Gaps / Not Yet Implemented
These are intentionally pending and should not be assumed present in production deployments today:
- Full audit/event logging store
- MFA (any form)
- LDAP/AD integration
- SAML encryption (signing only currently supported)
- Automated backups / restore tooling
- SCIM provisioning
- Dynamic client registration
- WebAuthn support
- Pluggable policy engine

## ❗ Breaking Change Policy
- Management API changes that remove or rename fields require a version bump (Accept header negotiation)
- Additive, non-breaking fields allowed without version increment (documented in OpenAPI spec)
- Deprecations must appear in spec with `deprecated: true` for one minor cycle before removal

## 🔐 Security Roadmap Snapshot
| Area | Current | Planned Next | Future |
|------|---------|--------------|--------|
| Token Issuance | JWT (RS256/ES256 TBD) | Key rotation scheduling | External KMS |
| MFA | None | TOTP | WebAuthn / FIDO2 |
| SAML | Signing | Encryption opt-in | Advanced bindings / policy |
| Logging | Basic internal visibility | Structured audit log | Streaming export |
| Provisioning | Manual / API | SCIM (users/groups) | Event-driven sync |

## ✅ Definition of Done (Feature Level)
A feature is only “Done” when:
1. Code implemented & formatted
2. Tests (happy path + edge + isolation) added & passing
3. No compiler warnings
4. OpenAPI spec updated (if API-related)
5. README / docs updated for user-visible impact
6. Roadmap updated if it moves an item’s status

## 🛡️ Contribution Guardrails
- No feature merges that degrade tenant isolation
- No silent security-impacting changes (must be documented)
- Favor explicit configuration over hidden defaults

## 📩 Feedback & Prioritization
Open issues with the `feature-request` label or start a discussion thread. High-signal production use cases and security improvements are prioritized over cosmetic UI changes.

---
Last updated: 2025-10-07
