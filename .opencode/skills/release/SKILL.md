---
name: cut-release
description: Use when cutting a new Authify release. Triggers on requests to "cut a release", "release vX.Y.Z", "bump the version", "make a new release", "tag a release", or "publish a release". Covers updating mix.exs and CHANGELOG.md, tagging, and pushing to trigger the automated GitHub Actions release.
---

# Cutting an Authify Release

Authify uses a GitHub Actions workflow (`.github/workflows/release.yml`) that
is triggered by pushing a `v*` tag. Pushing the tag automatically:
1. Builds and pushes a multi-arch Docker image to `ghcr.io/authify/authify`.
2. Generates a changelog from commits since the previous tag.
3. Creates the GitHub Release with that changelog.

**You do NOT create the GitHub Release manually.** Your job is to bump the
version, update the changelog, commit, and push the tag.

## Your steps

### 1. Determine the version bump

- Read the current version from `mix.exs` (`version: "..."`).
- Check what changed since the last tag: `git log --oneline <last_tag>..HEAD`.
- Bump per SemVer:
  - Breaking change → **major** bump.
  - New feature / significant refactor (non-breaking) → **minor** bump.
  - Bug fix / small change → **patch** bump.

### 2. Update `mix.exs`

Bump the `version:` field to the new version.

### 3. Update `CHANGELOG.md`

Follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

- Replace the `## [Unreleased]` heading with `## [<new_version>] - <YYYY-MM-DD>`
  and fill in the notable changes under it (Added / Changed / Fixed sections).
- Add a fresh `## [Unreleased]` heading above it for future work.
- Update the version compare links at the bottom of the file:
  - Change `[Unreleased]: .../compare/v<prev>...HEAD` → `[Unreleased]: .../compare/v<new>...HEAD`
  - Add `[<new_version>]: .../compare/v<prev>...v<new>`

### 4. Commit and push

```bash
git add mix.exs CHANGELOG.md
git commit -m "chore: release v0.x.y"
git push
git tag v0.x.y
git push origin v0.x.y
```

The tag push triggers the release workflow. No manual GitHub release creation
is needed.

## Verify

After pushing the tag, confirm the release workflow runs:
`gh run list --branch <tag_name>` or check the GitHub Actions tab / Releases page.
