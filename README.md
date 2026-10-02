# Unified Repository Risk & Analysis Orchestrator (`tech-risk`)

A centralized security, statutory compliance, and code quality governance platform that orchestrates static analysis tools across Git repositories via GitHub Actions, performs AI-assisted semantic finding analysis, tracks token usage/costs, and presents telemetry through a REST API and React UI dashboard.

> **Note**: This system performs automated risk scanning and statutory rule evaluation to assist development teams. It does not provide legal advice, legal compliance certification, or guaranteed security immunity.

---

## 📖 Documentation Quick Links

- **User & Functional Documentation**: Read this file (`README.md`).
- **Developer & Technical Documentation**: Read [`DEVELOPER_README.md`](DEVELOPER_README.md) for architecture, API schemas, local environment setup, and extension guides.

---

## 🌟 Key Capabilities & System Features

1. **Multi-Ecosystem Static Analysis Orchestration**:
   - Executes Python tools (Ruff, Bandit, Pip-audit, Mypy, Pytest, Import-Linter), JS/React tools (Snyk Open Source, OWASP dep-scan, Dependency-Cruiser, React Doctor, Deslint), and multi-language SAST (Semgrep, SonarQube).
   - Automatically detects project languages and gracefully skips non-applicable tools.
   - Isolates tool execution errors so a single scanner failure never halts the overall pipeline.

2. **Compliance & Statutory Risk Detection**:
   - Built-in compliance classification engines evaluating code against regulatory frameworks: **GDPR**, **DPDP Act 2023**, **EU Cyber Resilience Act (CRA)**, **SPDI Rules**, **TCPA**, and **TRAI DLT**.

3. **AI Semantic Reasoning & Secret Redaction**:
   - Enriches findings with AI-assisted severity evaluation, contextual explanation, and remediation suggestions using Gemini or OpenAI models.
   - Features automated secret redaction before sending code contexts to LLM APIs.

4. **Token Telemetry & Cost Visibility**:
   - Calculates prompt/candidate token consumption and USD costs per model tier (Gemini 3.5 Flash, GPT-4, etc.) based on actual usage telemetry.

5. **Automated Organization Onboarding & Drift Control**:
   - Bulk-onboards GitHub organizations or accounts by creating standardized caller workflow pull requests (`.github/workflows/code-analysis.yml`).
   - Detects workflow drift and protects customized target workflows with custom jobs from automated overwrites.

6. **Targeted Finding Rechecks**:
   - Allows users to dispatch lightweight, single-finding revalidation jobs on targeted commit SHAs directly from the UI or API.

7. **Centralized REST API & React Dashboard**:
   - Browse repository risk profiles, run summaries, findings severity breakdown, AI cost metrics, download reports/artifacts (JSON, CSV, ZIP), and trigger targeted rechecks.

---

## 🚀 System Workflows & Operations

### 1. Repository Onboarding Workflow
To onboard target repositories to the central analysis pipeline:

#### Option A: Bulk Onboarding CLI (`onboard_org.py`)
Run the Python onboarding CLI against an organization, user, or single repository:
```bash
export GITHUB_TOKEN="your_github_token"
python onboard_org.py --org Heydo-Tech --check-drift --fix-drift
```

**Required `GITHUB_TOKEN` Permissions**:
- `Contents`: Read & Write (to create onboarding setup branches and commit workflow files).
- `Workflows`: Read & Write (required by GitHub API when committing files under `.github/workflows/`).
- `Pull Requests`: Read & Write (to open onboarding PRs).
- `Organization / User Repositories`: Read (to discover repositories).

**Status Classifications**:
- `UP_TO_DATE`: Workflow matches canonical configuration.
- `NEEDS_ONBOARDING`: Creates a setup branch and Pull Request on the target repository.
- `DRIFT`: Identifies outdated central workflow references and creates update PRs when `--fix-drift` is passed.
- `CUSTOMIZED`: Skips repositories with custom jobs to prevent overwriting user logic and flags them for manual review.

#### Option B: Standalone Shell Script (`onboard.sh`)
Target repository maintainers can execute `onboard.sh` directly inside their repository:
```bash
bash onboard.sh
```

---

### 2. Code Analysis Pipeline (`.github/workflows/code-analysis.yml`)
Once onboarded, target repositories execute the central pipeline on `push`, `pull_request`, or `workflow_dispatch`.

#### Canonical Caller Workflow
```yaml
name: Code Analysis

on:
  push:
  pull_request:
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
    if: ${{ github.event_name != 'workflow_dispatch' || inputs.recheck_finding_id == '' }}
    uses: manasvipaweria/tech-risk/.github/workflows/reusable-analysis.yml@main
    with:
      enable_codex: true
      enable_design_ai: true
      enable_deslint: true
      run_id: ${{ github.event.inputs.run_id }}
    secrets:
      SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
      ANALYSIS_BACKEND_URL: ${{ secrets.ANALYSIS_BACKEND_URL }}
      ANALYSIS_SECRET: ${{ secrets.ANALYSIS_SECRET }}
  recheck:
    if: ${{ github.event_name == 'workflow_dispatch' && inputs.recheck_finding_id != '' }}
    uses: manasvipaweria/tech-risk/.github/workflows/reusable-finding-recheck.yml@main
    with:
      finding_id: ${{ inputs.recheck_finding_id }}
      attempt_id: ${{ inputs.recheck_attempt_id }}
      tool: ${{ inputs.recheck_tool }}
      rule_id: ${{ inputs.recheck_rule_id }}
      file_path: ${{ inputs.recheck_file_path }}
      line_start: ${{ inputs.recheck_line_start }}
      line_end: ${{ inputs.recheck_line_end }}
      commit_sha: ${{ inputs.recheck_commit_sha }}
    secrets:
      SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      ANALYSIS_BACKEND_URL: ${{ secrets.ANALYSIS_BACKEND_URL }}
      ANALYSIS_SECRET: ${{ secrets.ANALYSIS_SECRET }}
```

---

### 3. Targeted Finding Recheck Workflow
When a developer addresses a specific security or quality finding, they can initiate a targeted recheck without running a full repository scan.

- **Triggering via UI/API**: Select a finding in the React Dashboard and click **Recheck Finding**.
- **Execution**: Dispatches the `recheck` job in `.github/workflows/reusable-finding-recheck.yml` targeting the specified file path and commit SHA.
- **Result Statuses**:
  - `FIXED`: Finding is no longer present on the target commit.
  - `STILL_PRESENT`: Finding persists.
  - `FAILED`: Recheck was inconclusive or tool execution failed.

---

### 4. Viewing Telemetry & Downloading Reports
1. **React Dashboard**: Open `http://localhost:5173` (or production URL) to view repository lists, run details, findings breakdown, and collapsible AI Usage / Cost & Token Visibility cards.
2. **Report Downloads**: Download complete reports and artifacts in multiple formats:
   - **JSON**: `/api/reports/{run_id}/download/json`
   - **CSV**: `/api/reports/{run_id}/download/csv`
   - **ZIP Archive**: `/api/reports/{run_id}/download/zip` (or `/api/reports/{run_id}/download/artifact`)

---

## 🖥️ Local System Setup & Running the Dashboard

### 1. Start FastAPI Backend Server
```bash
# Set database connection string (optional; falls back to SQLite/in-memory if unconfigured)
export DATABASE_URL="postgresql://postgres:password@localhost:5432/repo_analysis"

# Launch backend API server
uvicorn src.api.server:app --host 0.0.0.0 --port 8000 --reload
```

### 2. Start React Frontend Dashboard
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` in your browser.

---

## 🔐 Credentials & Required Permissions

| Context | Required Credentials / Secrets | Scope / Purpose |
| :--- | :--- | :--- |
| **GitHub Actions Runner** | `GEMINI_API_KEY`, `OPENAI_API_KEY` | Access to Gemini 3.5 / OpenAI APIs for AI analysis |
| **Snyk Scanning** | `SNYK_TOKEN` | Access to Snyk vulnerability database |
| **Backend Callback** | `ANALYSIS_BACKEND_URL`, `ANALYSIS_SECRET` | Backend endpoint authentication for run ingestion |
| **Organization Onboarding** | `GITHUB_TOKEN` | `Contents:write`, `Workflows:write`, `Pull Requests:write` |

---

## 🛠️ Local CLI Usage

Run the orchestrator directly from the command line against any local folder or public repository URL:

```bash
# Basic run
python analyze_repo.py https://github.com/user/repo

# Selective tools & AI analysis
python analyze_repo.py . --tools ruff,bandit,semgrep --run-ai

# Local PostgreSQL persistence
export DATABASE_URL="postgresql://postgres:password@localhost:5432/repo_analysis"
python analyze_repo.py . --repo-name Heydo-Tech/example --tools ruff --output json --persist
```

### Verified CLI Options

#### `analyze_repo.py` Options
- `repo_url`: URL or local path of the repository to analyze.
- `--repo-name REPO_NAME`: Report identifier when analyzing a local directory.
- `--branch BRANCH`: Branch or commit to check out.
- `--tools TOOLS`: Comma-separated list of tools to run.
- `--output OUTPUT`: Output report formats (`json`, `csv`).
- `--run-ai`: Run AI post-processing stage.
- `--persist`: Store report in PostgreSQL.
- `--database-url DATABASE_URL`: PostgreSQL connection string.
- `--commit-sha COMMIT_SHA`, `--workflow-run-id WORKFLOW_RUN_ID`, `--run-id RUN_ID`: Internal metadata.
- `--backend-url BACKEND_URL`: Backend API URL for status callbacks.

#### `onboard_org.py` Options
- `--org ORG`: Target an entire GitHub Organization.
- `--owner OWNER`: Target a GitHub personal account/user.
- `--repo REPO`: Target a specific repository (`owner/repo`).
- `--dry-run`: Preview changes without creating branches or PRs.
- `--limit LIMIT`: Maximum number of PRs to create.
- `--check-drift`: Only check for workflow drift.
- `--fix-drift`: Create PRs to fix drifted repositories.
- `--orchestrator-ref ORCHESTRATOR_REF`: Reusable workflow ref (defaults to `main`).

---

## 💻 Developer Guide & Technical Reference

For comprehensive developer documentation, repository architecture maps, backend API route specs, database schemas, testing strategies, and extension guides, please refer to [`DEVELOPER_README.md`](DEVELOPER_README.md).
