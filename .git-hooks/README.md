# Git Hooks for Authify

This directory contains git hooks that help maintain code quality during development.

## Installation

To install the hooks, run:

```bash
./.git-hooks/install.sh
```

This will copy the hooks to `.git/hooks/` and make them executable.

## Available Hooks

### pre-commit

Runs before each commit to ensure code quality. This hook runs `mix precommit.fast` which includes:

- **Compilation** - Ensures code compiles with warnings treated as errors
- **Format check** - Verifies code is properly formatted
- **Credo** - Static code analysis for style and best practices
- **Sobelow** - Security vulnerability scanning

**Note:** The hook intentionally skips tests to keep commits fast. Always run `mix precommit` (with tests) before pushing or opening a pull request.

## Bypassing Hooks

If you need to bypass the pre-commit hook (not recommended):

```bash
git commit --no-verify
```

## Mix Tasks

The project includes two precommit tasks:

- `mix precommit` - Full checks including tests (slow but comprehensive)
- `mix precommit.fast` - Fast checks without tests (used by git hook)

## Why Skip Tests in the Hook?

Running the full test suite on every commit would be too slow and interrupt the development flow. The fast checks catch most common issues (formatting, syntax errors, style violations) while keeping commits quick.

**Important:** Always run the full `mix precommit` with tests before:
- Pushing to the remote repository
- Opening a pull request
- Making a release

This ensures all tests pass and the codebase remains in a healthy state.
