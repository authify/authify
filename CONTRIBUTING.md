# Contributing to Authify

Thanks for your interest in contributing! This document lays out the expectations and workflow so contributions are smooth, high‑quality, and production‑ready.

## Core Principles
- **Security first** – Never weaken auth, token, SAML, or multi‑tenant isolation guarantees.
- **Tests over manual curl** – Every behavioral change must include or update automated tests.
- **Zero warnings policy** – Compiler warnings are treated as failures.
- **Determinism** – Avoid non‑deterministic tests (timing, ordering, sleeps) unless absolutely necessary.
- **Minimal dependencies** – Prefer the standard library or existing deps unless there is a compelling reason.

## Project Scope (Quick Summary)
Authify is a multi‑tenant identity provider offering OAuth2/OIDC and SAML 2.0 with a Management API, per‑organization configuration, and secure defaults.

## Getting Started
1. **Fork the repo** and clone your fork.
2. Install dependencies:
   ```bash
   mix deps.get
   npm install --prefix assets
   ```
3. Setup the database:
   ```bash
   mix ecto.setup
   ```
4. **(Recommended)** Install git hooks for automatic pre-commit checks:
   ```bash
   ./.git-hooks/install.sh
   ```
   This will run fast quality checks (formatting, compilation, credo, sobelow) before each commit, catching issues early.
5. Run the server (optional while developing backend logic):
   ```bash
   mix phx.server
   ```
6. Run tests to ensure a clean baseline:
   ```bash
   mix test
   ```

## Branching & Commits
- Use feature branches: `feature/<short-description>` or `fix/<short-description>`
- Follow **Conventional Commits**:
  - `feat: add OAuth client rotation endpoint`
  - `fix: correct SAML NameID format handling`
  - `docs: update rate limiting guidance`
  - `refactor: extract token scope normalizer`
  - `test: add SLO multi-session coverage`
  - `chore: bump dependency versions`
- Keep commits focused and logically grouped; avoid giant “mixed changes” commits.

## Development Workflow
1. Write or update tests **first** (TDD strongly encouraged).
2. Implement code changes.
3. Ensure formatting & code health:
   ```bash
   mix format
   mix compile --warnings-as-errors
   ```
4. Run full test suite (unit + integration + protocol flows):
   ```bash
   mix test
   ```
5. (Optional) Run security & static analysis:
   ```bash
   mix sobelow --exit
   ```
6. Before committing, run quality checks:
   ```bash
   # Fast checks (no tests) - runs automatically if you installed git hooks
   mix precommit.fast

   # Full checks including tests (recommended before pushing)
   mix precommit
   ```
7. Open a Pull Request with a clear description (see below).

### Git Pre-commit Hooks
If you ran `./.git-hooks/install.sh` during setup, the pre-commit hook will automatically run `mix precommit.fast` before each commit. This catches formatting, compilation, and code quality issues early without the time cost of running the full test suite.

**What the hook checks:**
- Code compilation with warnings as errors
- Code formatting (`mix format`)
- Credo static analysis
- Sobelow security checks

**To bypass the hook** (not recommended):
```bash
git commit --no-verify
```

**Note:** The hook runs fast checks only. Always run `mix precommit` (with tests) before pushing or opening a PR.

## Pull Request Guidelines
A good PR includes:
- **Summary** – What changed and why.
- **Scope** – Which part(s) of the system (OAuth, SAML, API, UI, config, rate limiting).
- **Testing** – Outline of added tests and coverage areas.
- **Security Impact** – Any effects on crypto, token issuance, isolation, or exposure.
- **Docs** – Note any README / ROADMAP / API spec updates.

PRs may be declined or requested for revision if:
- Missing or incomplete tests.
- Introduces warnings or dialyzer regressions (if dialyzer enabled locally).
- Adds external dependencies without justification.
- Mixes unrelated concerns (split them up!).

## Testing Standards
- **Unit tests** for pure modules & helpers.
- **Integration tests** for OAuth flows, SAML flows, Management API endpoints, multi‑tenant boundaries.
- **Regression tests** when fixing bugs.
- Avoid asserting on large HTML blobs; prefer element existence and structural assertions.
- Multi‑tenant tests must prove isolation (Org A cannot see Org B data/tokens/apps).

## Management API Changes
When adding/altering endpoints:
1. Add or modify controller + route.
2. Update OpenAPI generator logic (`docs_controller.ex`).
3. Add request/response schema changes.
4. Add full test coverage (success + edge + permission denial + validation errors).
5. Update README examples if user‑facing.
6. Increment version semantics if a breaking change (Accept header semantics).

## Rate Limiting Changes
If you modify or extend rate limiting:
- Provide tests for exceed / near‑limit / reset conditions.
- Document new configuration options (README + ROADMAP if strategic).
- Ensure cached config invalidates correctly.
- Avoid global contention; preserve per‑org isolation.

## SAML Changes
- Maintain correct XML canonicalization & signatures.
- Include tests for modified bindings (Redirect, POST) and SLO flows.
- If adding encryption support: document key management & update security section.

## Security Expectations
- No plaintext secrets committed.
- Never call `String.to_atom/1` on user input.
- Validate all external parameters (query/body) via changesets or explicit validation functions.
- Enforce scope checks in Management API endpoints.
- Keep dependency updates frequent to minimize vulnerability windows.

## Style & Conventions
- Predicate functions end in `?` (not `is_` unless guard macro).
- Do not access struct fields using map access syntax.
- Avoid nesting modules in a single file.
- Prefer `Task.async_stream` for controlled concurrency with back‑pressure.

## Documentation
- Update `ROADMAP.md` only for strategic changes (features on or off the roadmap).
- README changes for user‑visible capabilities only after implementation passes tests.
- Include usage examples where helpful.

## Performance Considerations
- Avoid N+1 queries – preload associations when rendering collections.
- Use streams in LiveView for large collections (per existing project guidelines).
- Benchmark before introducing caching; justify with numbers.

## Opening an Issue
Include:
- Environment (Elixir, OTP, DB, platform).
- Reproduction steps (minimal sequence).
- Expected vs actual behavior.
- Logs or stack traces (scrub sensitive values).

## Becoming a Maintainer
Regular, high‑quality contributions + code reviews + roadmap alignment discussions may lead to maintainer invitation.

## Code of Conduct
Be respectful, constructive, and security‑minded. (A formal CODE_OF_CONDUCT.md can be added later.)

## Creating Releases

**Note:** Only maintainers with push access can create releases.

Authify uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and automated GitHub Actions workflows for releases.

### Release Checklist

1. **Update the version in `mix.exs`:**
   ```elixir
   version: "0.4.0",  # Update this line (currently at line 7)
   ```

2. **Update `CHANGELOG.md`:**
   - Move items from `[Unreleased]` to a new version section
   - Follow the existing format ([Keep a Changelog](https://keepachangelog.com/))
   - Use categories: Added, Changed, Deprecated, Removed, Fixed, Security
   - Include the release date in ISO format (YYYY-MM-DD)

   Example:
   ```markdown
   ## [Unreleased]

   ## [0.4.0] - 2025-12-04

   ### Changed
   - Updated Elixir to 1.19.4

   ### Added
   - New feature description
   ```

3. **Run full quality checks:**
   ```bash
   mix precommit
   ```
   Ensure all tests pass and there are no warnings.

4. **Commit the version bump:**
   ```bash
   git add mix.exs CHANGELOG.md
   git commit -m "chore(release): update version to 0.4.0"
   ```

5. **Create and push the release tag:**
   ```bash
   # Create an annotated tag
   git tag -a v0.4.0 -m "Release v0.4.0"

   # Push the commit and tag
   git push origin main
   git push origin v0.4.0
   ```

6. **Automated release process:**
   Once the tag is pushed, the `.github/workflows/release.yml` workflow automatically:
   - Builds the Docker image for multiple architectures
   - Pushes image to GitHub Container Registry with tags:
     - `ghcr.io/authify/authify:v0.4.0` (exact version)
     - `ghcr.io/authify/authify:0.4` (minor version)
     - `ghcr.io/authify/authify:0` (major version)
     - `ghcr.io/authify/authify:sha-<commit>` (commit hash)
   - Creates a GitHub Release with auto-generated changelog from commits
   - Links to the Docker image in the release notes

7. **Verify the release:**
   - Check the [Releases page](https://github.com/authify/authify/releases)
   - Verify the Docker image: `docker pull ghcr.io/authify/authify:v0.4.0`
   - Review the auto-generated changelog

### Version Number Guidelines

- **Patch version (0.3.1):** Bug fixes, security patches, minor improvements
- **Minor version (0.4.0):** New features, non-breaking changes
- **Major version (1.0.0):** Breaking changes, major milestones

### Common Issues

- **Forgot to update version:** Create a new patch version with the corrected version number
- **Failed Docker build:** Check the Actions tab for build logs; common issues include dependency conflicts or missing assets
- **Wrong tag pushed:** Delete the tag locally and remotely, fix the issue, and re-tag:
  ```bash
  git tag -d v0.4.0
  git push origin :refs/tags/v0.4.0
  ```

## License
By contributing you agree your contributions are licensed under the MIT License included in this repository.

---
Thank you for helping build Authify!
