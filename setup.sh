#!/usr/bin/env bash
set -euo pipefail

#
# One-click setup for CodeQL Devin Fixer
#
# This script creates the GitHub Actions workflow file in your repository,
# guides you through secret configuration, and optionally runs a dry-run
# scan to verify everything works.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/marius-posa/codeql-devin-fixer/main/setup.sh | bash
#   # or
#   ./setup.sh
#

WORKFLOW_DIR=".github/workflows"
WORKFLOW_FILE="$WORKFLOW_DIR/codeql-fixer.yml"
ACTION_REF="${CODEQL_FIXER_REF:-marius-posa/codeql-devin-fixer@main}"

echo "============================================"
echo "  CodeQL Devin Fixer - Setup"
echo "============================================"
echo ""

if [ ! -d ".git" ]; then
  echo "ERROR: This script must be run from the root of a Git repository."
  echo "  cd /path/to/your/repo && bash setup.sh"
  exit 1
fi

REPO_URL=$(git remote get-url origin 2>/dev/null || echo "")
if [ -z "$REPO_URL" ]; then
  echo "WARNING: No git remote 'origin' found. You'll need to set the target_repo manually."
fi

echo "Repository: ${REPO_URL:-<no remote>}"
echo ""

if [ -f "$WORKFLOW_FILE" ]; then
  echo "Workflow file already exists: $WORKFLOW_FILE"
  read -rp "Overwrite? [y/N] " overwrite
  if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
    echo "Keeping existing workflow file."
    echo ""
  fi
else
  overwrite="y"
fi

if [[ "$overwrite" =~ ^[Yy]$ ]] || [ ! -f "$WORKFLOW_FILE" ]; then
  mkdir -p "$WORKFLOW_DIR"

  read -rp "Action reference [${ACTION_REF}]: " custom_ref
  ACTION_REF="${custom_ref:-$ACTION_REF}"

  cat > "$WORKFLOW_FILE" << WORKFLOW_EOF
name: CodeQL Devin Fixer

on:
  workflow_dispatch:
    inputs:
      target_repo:
        description: "GitHub repository URL or owner/repo to analyze"
        required: true
        type: string
      severity_threshold:
        description: "Minimum severity: critical, high, medium, low"
        required: false
        type: choice
        options:
          - critical
          - high
          - medium
          - low
        default: "low"
      batch_size:
        description: "Max issues per Devin session"
        required: false
        type: number
        default: 5
      max_sessions:
        description: "Max Devin sessions to create"
        required: false
        type: number
        default: 5
      dry_run:
        description: "Generate prompts only (no Devin sessions)"
        required: false
        type: boolean
        default: false

permissions:
  contents: write
  security-events: write

jobs:
  analyze-and-fix:
    name: Analyze & Dispatch Fixes
    runs-on: ubuntu-latest
    timeout-minutes: 120
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Run CodeQL Devin Fixer
        uses: ${ACTION_REF}
        with:
          target_repo: \${{ inputs.target_repo }}
          severity_threshold: \${{ inputs.severity_threshold }}
          batch_size: \${{ inputs.batch_size }}
          max_sessions: \${{ inputs.max_sessions }}
          dry_run: \${{ inputs.dry_run }}
          github_token: \${{ secrets.GH_PAT }}
          devin_api_key: \${{ secrets.DEVIN_API_KEY }}
WORKFLOW_EOF

  echo "Created: $WORKFLOW_FILE"
  echo ""
fi

echo "============================================"
echo "  Secret Configuration"
echo "============================================"
echo ""
echo "You need to add these secrets to your repository:"
echo ""
echo "  1. DEVIN_API_KEY  - Your Devin API key"
echo "     Get one at: https://docs.devin.ai/api-reference/overview"
echo ""
echo "  2. GH_PAT         - GitHub Personal Access Token with 'repo' scope"
echo "     Create at: https://github.com/settings/tokens"
echo ""
echo "Add them at:"
echo "  https://github.com/$(git remote get-url origin 2>/dev/null | sed 's|.*github.com[:/]||;s|\.git$||')/settings/secrets/actions"
echo ""

if command -v gh &>/dev/null; then
  read -rp "Set secrets now using GitHub CLI? [y/N] " set_secrets
  if [[ "$set_secrets" =~ ^[Yy]$ ]]; then
    echo ""
    echo "Setting DEVIN_API_KEY..."
    gh secret set DEVIN_API_KEY
    echo ""
    echo "Setting GH_PAT..."
    gh secret set GH_PAT
    echo ""
    echo "Secrets configured."
  fi
else
  echo "Tip: Install the GitHub CLI (gh) to set secrets from the command line."
fi

echo ""
echo "============================================"
echo "  Optional: Per-Repo Configuration"
echo "============================================"
echo ""
read -rp "Create a .codeql-fixer.yml config file? [y/N] " create_config
if [[ "$create_config" =~ ^[Yy]$ ]]; then
  cat > ".codeql-fixer.yml" << 'CONFIG_EOF'
# CodeQL Devin Fixer - Per-repo configuration
# This file overrides default action settings for this repository.
# See: https://github.com/marius-posa/codeql-devin-fixer#per-repo-configuration

severity_threshold: low
batch_size: 5
max_sessions: 10

# Glob patterns to exclude from analysis
# exclude_paths:
#   - "vendor/**"
#   - "node_modules/**"
#   - "**/*.test.js"

# Custom CWE-to-family mappings (extend built-in families)
# cwe_families:
#   my-custom-family:
#     - cwe-999
#     - cwe-998
CONFIG_EOF
  echo "Created: .codeql-fixer.yml"
fi

echo ""
echo "============================================"
echo "  Dry Run Verification"
echo "============================================"
echo ""
read -rp "Trigger a dry-run scan now? (requires gh CLI and secrets set) [y/N] " dry_run
if [[ "$dry_run" =~ ^[Yy]$ ]]; then
  if ! command -v gh &>/dev/null; then
    echo "ERROR: GitHub CLI (gh) is required for dry-run. Install it from https://cli.github.com/"
    exit 1
  fi

  TARGET="${REPO_URL:-$(git remote get-url origin 2>/dev/null || echo '')}"
  if [ -z "$TARGET" ]; then
    read -rp "Target repo URL: " TARGET
  fi

  echo "Triggering dry-run for: $TARGET"
  gh workflow run "CodeQL Devin Fixer" \
    -f target_repo="$TARGET" \
    -f dry_run=true

  echo ""
  echo "Dry-run triggered! Check the Actions tab in your repository."
fi

echo ""
echo "============================================"
echo "  Setup Complete"
echo "============================================"
echo ""
echo "Next steps:"
echo "  1. Ensure secrets (DEVIN_API_KEY, GH_PAT) are configured"
echo "  2. Push the workflow file: git add $WORKFLOW_FILE && git commit -m 'Add CodeQL Devin Fixer workflow' && git push"
echo "  3. Go to Actions > CodeQL Devin Fixer > Run workflow"
echo ""
echo "Documentation: https://github.com/marius-posa/codeql-devin-fixer"
echo ""
