#!/bin/bash
# Install git hooks for Authify development

HOOKS_DIR=".git-hooks"
GIT_HOOKS_DIR=".git/hooks"

echo "Installing Authify git hooks..."

# Create .git/hooks directory if it doesn't exist
mkdir -p "$GIT_HOOKS_DIR"

# Install pre-commit hook
if [ -f "$HOOKS_DIR/pre-commit" ]; then
    cp "$HOOKS_DIR/pre-commit" "$GIT_HOOKS_DIR/pre-commit"
    chmod +x "$GIT_HOOKS_DIR/pre-commit"
    echo "✓ Installed pre-commit hook"
else
    echo "✗ Warning: pre-commit hook not found in $HOOKS_DIR"
fi

echo ""
echo "Git hooks installed successfully!"
echo ""
echo "The pre-commit hook will run 'mix precommit.fast' before each commit."
echo "This includes: compile, format check, credo, and sobelow (but skips tests)."
echo ""
echo "To bypass the hook (not recommended): git commit --no-verify"
