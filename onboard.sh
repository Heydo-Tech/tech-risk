#!/usr/bin/env bash
set -e

echo "=== Code Analysis Repository Onboarding ==="

# Validate that the user is inside a Git repository
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "❌ Error: You must be inside a Git repository to onboard it."
    exit 1
fi

# Validate that an origin remote exists
if ! git config --get remote.origin.url >/dev/null 2>&1; then
    echo "❌ Error: Remote 'origin' does not exist. Please configure an origin remote."
    exit 1
fi

# Validate that the origin points to GitHub
ORIGIN_URL=$(git config --get remote.origin.url)
if [[ "$ORIGIN_URL" != *"github.com"* ]]; then
    echo "❌ Error: Remote 'origin' does not appear to point to GitHub ($ORIGIN_URL)."
    exit 1
fi

# Detect the repository's current/default branch
DEFAULT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ -z "$DEFAULT_BRANCH" ] || [ "$DEFAULT_BRANCH" = "HEAD" ]; then
    DEFAULT_BRANCH=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@^refs/remotes/origin/@@' || echo "main")
fi

echo "Repository detected. Default branch: $DEFAULT_BRANCH"

# Check whether .github/workflows/code-analysis.yml already exists
WORKFLOW_FILE=".github/workflows/code-analysis.yml"
if [ -f "$WORKFLOW_FILE" ]; then
    echo "❌ Error: The repository is already onboarded ($WORKFLOW_FILE exists)."
    echo "   Aborting to prevent overwriting existing configuration."
    exit 1
fi

# Create branch
TIMESTAMP=$(date +"%Y%m%d%H%M%S")
BRANCH_NAME="setup/code-analysis-$TIMESTAMP"
echo "Creating setup branch: $BRANCH_NAME"
git checkout -b "$BRANCH_NAME"

# Create workflow
mkdir -p .github/workflows

ORCHESTRATOR_OWNER="${ORCHESTRATOR_OWNER:-Heydo-Tech}"
ORCHESTRATOR_REPO="${ORCHESTRATOR_REPO:-tech-risk}"
ORCHESTRATOR_REF="${ORCHESTRATOR_REF:-main}"

# Triggers configuration
TRIGGERS="${TRIGGERS:-pull_request}"
if [ "$TRIGGERS" = "push,pull_request" ]; then
    ON_CONFIG="  push:
  pull_request:"
elif [ "$TRIGGERS" = "push" ]; then
    ON_CONFIG="  push:"
else
    ON_CONFIG="  pull_request:"
fi

cat <<YML_EOF > "$WORKFLOW_FILE"
name: Code Analysis

on:
$ON_CONFIG
  workflow_dispatch:
    inputs:
      run_id:
        description: 'Analysis Run ID'
        required: false
        type: string
      recheck_finding_id:
        description: 'Finding ID for a targeted recheck'
        required: false
        type: string
      recheck_attempt_id:
        required: false
        type: string
      recheck_tool:
        required: false
        type: string
      recheck_rule_id:
        required: false
        type: string
      recheck_file_path:
        required: false
        type: string
      recheck_line_start:
        required: false
        type: string
      recheck_line_end:
        required: false
        type: string
      recheck_commit_sha:
        required: false
        type: string

jobs:
  analysis:
    if: \${{ github.event_name != 'workflow_dispatch' || inputs.recheck_finding_id == '' }}
    uses: ${ORCHESTRATOR_OWNER}/${ORCHESTRATOR_REPO}/.github/workflows/reusable-analysis.yml@${ORCHESTRATOR_REF}
    with:
      enable_codex: true
      enable_design_ai: true
      enable_deslint: true
      run_id: \${{ github.event.inputs.run_id }}
    secrets:
      SNYK_TOKEN: \${{ secrets.SNYK_TOKEN }}
      GEMINI_API_KEY: \${{ secrets.GEMINI_API_KEY }}
      OPENAI_API_KEY: \${{ secrets.OPENAI_API_KEY }}
      ANALYSIS_BACKEND_URL: \${{ secrets.ANALYSIS_BACKEND_URL }}
      ANALYSIS_SECRET: \${{ secrets.ANALYSIS_SECRET }}
  recheck:
    if: \${{ github.event_name == 'workflow_dispatch' && inputs.recheck_finding_id != '' }}
    uses: ${ORCHESTRATOR_OWNER}/${ORCHESTRATOR_REPO}/.github/workflows/reusable-finding-recheck.yml@${ORCHESTRATOR_REF}
    with:
      finding_id: \${{ inputs.recheck_finding_id }}
      attempt_id: \${{ inputs.recheck_attempt_id }}
      tool: \${{ inputs.recheck_tool }}
      rule_id: \${{ inputs.recheck_rule_id }}
      file_path: \${{ inputs.recheck_file_path }}
      line_start: \${{ inputs.recheck_line_start }}
      line_end: \${{ inputs.recheck_line_end }}
      commit_sha: \${{ inputs.recheck_commit_sha }}
    secrets:
      SNYK_TOKEN: \${{ secrets.SNYK_TOKEN }}
      ANALYSIS_BACKEND_URL: \${{ secrets.ANALYSIS_BACKEND_URL }}
      ANALYSIS_SECRET: \${{ secrets.ANALYSIS_SECRET }}
YML_EOF

echo "✅ Created workflow at: $WORKFLOW_FILE"

# Commit generated workflow
git add "$WORKFLOW_FILE"
git commit -m "ci: add central Code Analysis workflow" >/dev/null
echo "✅ Committed workflow configuration."

# Push branch
echo "Pushing branch $BRANCH_NAME to origin..."
if ! git push -u origin "$BRANCH_NAME"; then
    echo "⚠️  Warning: Failed to push branch to origin. You may need to push it manually."
fi

# GitHub CLI Check / Secret Check
HAS_GH=false
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    HAS_GH=true
fi

echo ""
echo "=== Secret Visibility Check ==="
if [ "$HAS_GH" = true ]; then
    echo "Checking secrets via GitHub API..."
    # 'gh secret list' only shows repository-level secrets.
    # To check effective access, we query both the repository and shared organization secrets APIs.
    
    REPO_SECRETS=$(gh api repos/:owner/:repo/actions/secrets --jq '.secrets[].name' 2>/dev/null || echo "")
    ORG_SECRETS=$(gh api repos/:owner/:repo/actions/organization-secrets --jq '.secrets[].name' 2>/dev/null || echo "")
    
    ALL_SECRETS=$(echo -e "$REPO_SECRETS\n$ORG_SECRETS")
    
    if echo "$ALL_SECRETS" | grep -q "GEMINI_API_KEY"; then
        echo "✅ GEMINI_API_KEY is available to this repository."
    else
        echo "⚠️  GEMINI_API_KEY could not be found via the GitHub API."
        echo "   Please ensure it is set as a Repository secret or an Organization secret granted to this repo."
    fi

    if echo "$ALL_SECRETS" | grep -q "SNYK_TOKEN"; then
        echo "✅ SNYK_TOKEN is available to this repository."
    else
        echo "⚠️  SNYK_TOKEN could not be found via the GitHub API."
        echo "   Please ensure it is set as a Repository secret or an Organization secret granted to this repo."
    fi
else
    echo "⚠️  GitHub CLI (gh) is not available or not authenticated."
    echo "   Could not automatically verify if GEMINI_API_KEY and SNYK_TOKEN are available."
    echo "   Please verify manually in your repository settings."
fi

# PR creation
echo ""
echo "=== Pull Request ==="
if [ "$HAS_GH" = true ]; then
    echo "Creating Pull Request..."
    if gh pr create --title "Setup Code Analysis Workflow" \
                 --body "This PR onboards the repository to the central security and AI code analysis pipeline." \
                 --base "$DEFAULT_BRANCH" \
                 --head "$BRANCH_NAME"; then
        echo "✅ Pull Request created successfully!"
    else
        echo "⚠️  Failed to create Pull Request via GitHub CLI. Please create it manually."
    fi
else
    echo "✅ Branch pushed to origin."
    echo "⚠️  Could not create Pull Request automatically because 'gh' is not authenticated."
    echo "   Please create a Pull Request manually for branch: $BRANCH_NAME"
fi

echo ""
echo "🎉 Onboarding step complete."
