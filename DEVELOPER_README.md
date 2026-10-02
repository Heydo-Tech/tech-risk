# Technical Developer Guide — `tech-risk`

This document provides a comprehensive technical overview of the `tech-risk` repository architecture, component interactions, database schemas, API contracts, local development setup, testing strategies, and extension guides for core developers.

---

## 1. System Architecture & High-Level Data Flow

The `tech-risk` system operates as a centralized security, compliance, and code quality governance hub. It orchestrates static analysis tools across target repositories via GitHub Actions, persists structured findings to PostgreSQL, provides AI-assisted remediation suggestions, and presents telemetry via a REST API and React UI dashboard.

```mermaid
flowchart TD
    subgraph Target GitHub Repository
        A[Code Push / PR / Dispatch] --> B[Caller Workflow: code-analysis.yml]
    end

    subgraph GitHub Actions Runner
        B --> C[Central Reusable Workflow: reusable-analysis.yml / reusable-finding-recheck.yml]
        C --> D[Python Orchestrator: analyze_repo.py]
        D --> E[Static Analyzers & AI Adapters]
        E --> F[Report Generator: report.json / report.csv]
        F --> G[Backend Callback: /api/analysis/runs/{id}/report]
    end

    subgraph Backend Infrastructure & Storage
        G --> H[FastAPI Backend Server: src/api/server.py]
        H --> I[(PostgreSQL Database)]
        J[React Frontend UI: frontend/src/App.jsx] <--> H
    end
```

---

## 2. Directory Structure & Key Components

```
tech-risk/
├── .github/
│   └── workflows/
│       ├── code-analysis.yml             # Local caller workflow template for orchestrator testing
│       ├── reusable-analysis.yml         # Reusable analysis pipeline for target repositories
│       └── reusable-finding-recheck.yml  # Reusable targeted finding recheck pipeline
├── frontend/                             # React + Vite web dashboard UI
│   ├── src/
│   │   ├── App.jsx                       # Main frontend dashboard UI & state management
│   │   └── main.jsx                      # App entry point
│   └── package.json                      # Frontend dependencies
├── src/
│   ├── adapters/                         # Tool adapters converting raw scanner outputs into normalized Findings
│   │   ├── base.py                       # Abstract BaseAdapter contract
│   │   ├── ruff_adapter.py               # Ruff linter adapter
│   │   ├── bandit_adapter.py             # Bandit Python SAST adapter
│   │   ├── semgrep_adapter.py            # Semgrep multi-language SAST adapter
│   │   ├── pip_audit_adapter.py          # Pip-audit Python dependency vulnerability adapter
│   │   ├── snyk_adapter.py               # Snyk JS/Node dependency scanner adapter
│   │   ├── depscan_adapter.py            # OWASP dep-scan vulnerability adapter
│   │   ├── deslint_adapter.py            # Deslint React UI consistency adapter
│   │   ├── codex_security_adapter.py     # OpenAI Codex security adapter
│   │   ├── codex_architecture_adapter.py # OpenAI Codex architecture adapter
│   │   └── ...                           # Other static tool adapters
│   ├── ai/                               # AI post-processing & token tracking engine
│   │   ├── ai_adapter.py                 # Core AI analysis entry point
│   │   ├── report_processor.py           # Finding filter, secret redaction, and prompt builder
│   │   ├── usage_tracker.py              # Token usage and pricing calculation telemetry
│   │   └── providers/                    # Provider wrappers (Gemini, OpenAI, Mock)
│   ├── api/
│   │   └── server.py                     # FastAPI REST API server (runs, findings, rechecks, telemetry)
│   ├── compliance/                       # Statutory & regulatory mapping engines (GDPR, DPDP, CRA, SPDI, TCPA)
│   ├── core/
│   │   ├── models.py                     # Core Pydantic & Dataclass domain models (Finding, Report, ToolResult)
│   │   ├── onboarding.py                 # Canonical caller-workflow generator and drift classification
│   │   ├── pricing.py                    # Model pricing tables per 1M tokens
│   │   └── usage.py                      # Usage record persistence schemas
│   ├── storage/
│   │   └── postgres.py                   # PostgreSQL connection pooling, persistence, and querying logic
│   └── utils/
│       └── git.py                        # Git clone & repository utility helpers
├── analyze_repo.py                       # Main CLI entry point for running analysis locally
├── onboard_org.py                        # Bulk organization onboarding CLI script
├── onboard.sh                            # Standalone shell script for target repository onboarding
├── requirements.txt                      # Python dependencies
├── DEVELOPER_README.md                   # Technical developer guide (this file)
└── README.md                             # Functional user guide
```

---

## 3. Environment Variables & Secret Configuration

The following environment variables control server runtime, orchestrator execution, database connectivity, and credentials:

| Variable Name | Context | Purpose | Default / Example |
| :--- | :--- | :--- | :--- |
| `DATABASE_URL` | Server / CLI | PostgreSQL connection string | `postgresql://postgres:password@localhost:5432/repo_analysis` |
| `ANALYSIS_SECRET` | Backend / Actions | Shared bearer token for authenticating workflow callbacks | User-generated random secret |
| `ANALYSIS_BACKEND_URL` | Actions Runner | Base URL of the backend API for receiving completed reports | `https://api.yourdomain.com` |
| `ORCHESTRATOR_OWNER` | Onboarding | GitHub owner of the central orchestrator repo | `manasvipaweria` (or `Heydo-Tech`) |
| `ORCHESTRATOR_REPO` | Onboarding | Central orchestrator repo name | `tech-risk` |
| `GEMINI_API_KEY` | Actions / CLI | API key for Gemini AI analysis | — |
| `OPENAI_API_KEY` | Actions / CLI | API key for OpenAI Codex security scanners | — |
| `SNYK_TOKEN` | Actions Runner | Token for Snyk dependency scanning | — |
| `GITHUB_TOKEN` | Onboarding CLI | Personal access token or GitHub App token with repo/PR permissions | — |

---

## 4. PostgreSQL Database Schema & Persistence

PostgreSQL persistence is managed via [`src/storage/postgres.py`](src/storage/postgres.py). The schema initializes automatically on backend startup or when `--persist` is passed to `analyze_repo.py`.

### Primary Tables
1. **`analysis_runs`**: Stores individual workflow run records.
   - Key fields: `id` (UUID), `repository`, `branch`, `commit_sha`, `workflow_run_id`, `status` (`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`), `report` (`JSONB`), `summary_counts` (`JSONB`), `created_at`, `updated_at`.
2. **`findings`**: Stores individual normalized findings per run for targeted querying and rechecks.
   - Key fields: `id` (UUID), `run_id`, `rule_id`, `tool`, `severity`, `category`, `file_path`, `line_start`, `line_end`, `title`, `description`, `status` (`OPEN`, `FIXED`, `STILL_PRESENT`, `RECHECKING`), `fingerprint`.
3. **`ai_usage_records`**: Stores token telemetry and cost metrics per AI request.
   - Key fields: `id` (UUID), `run_id`, `provider`, `model`, `prompt_tokens`, `candidates_tokens`, `total_tokens`, `estimated_cost_usd`.
4. **`recheck_attempts`**: Stores history of targeted rechecks performed on specific findings.
   - Key fields: `id` (UUID), `finding_id`, `requested_commit_sha`, `checked_commit_sha`, `status`, `rechecked_at`.

---

## 5. Local Setup & Testing Commands

### Prerequisites
- Python 3.12+ (or 3.14)
- Node.js 20+ and npm
- PostgreSQL 14+ (optional for local non-persisted runs)

### Local Environment Setup
1. **Clone the repository**:
   ```bash
   git clone https://github.com/manasvipaweria/tech-risk.git
   cd tech-risk
   ```

2. **Install Python dependencies**:
   ```bash
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. **Install Frontend dependencies**:
   ```bash
   cd frontend
   npm install
   cd ..
   ```

### Running Unit & Regression Tests
Run the test suite via `pytest`:

- **Run Onboarding & Workflow Migration Tests**:
  ```bash
  python -m pytest tests/test_onboarding_migration.py tests/test_onboard_org.py -v
  ```

- **Run Targeted Recheck Tests**:
  ```bash
  python -m pytest tests/test_revalidation.py -v
  ```

- **Run Full Test Suite**:
  ```bash
  python -m pytest tests/
  ```

### Validating GitHub Actions Workflows
Perform **YAML syntax validation** locally via PyYAML (note: this validates YAML formatting and parsing syntax, not full GitHub Actions workflow schema validation):
```bash
python -c "import yaml, glob; [print(f'{f}: VALID') for f in glob.glob('.github/workflows/*.yml') if yaml.safe_load(open(f, encoding='utf-8'))]"
```

---

## 6. Development & Extension Guides

### Adding a New Static Analysis Tool Adapter
1. Create a new module in `src/adapters/` (e.g. `src/adapters/mytool_adapter.py`).
2. Subclass `BaseAdapter` from `src.adapters.base`:
   ```python
   from src.adapters.base import BaseAdapter
   from src.core.models import ToolResult, ToolStatus, Finding, Severity, Category

   class MyToolAdapter(BaseAdapter):
       @property
       def tool_name(self) -> str:
           return "mytool"

       @property
       def categories(self) -> list:
           return ["security"]

       def run(self, repo_path: str) -> ToolResult:
           # Subprocess call to execute tool
           # Convert native JSON/output to Finding instances
           return ToolResult(tool_name=self.tool_name, status=ToolStatus.COMPLETED, findings=[...])
   ```
3. Register your new adapter in `ALL_ADAPTERS` in `analyze_repo.py`.
4. Add default tool enablement to `DEFAULT_ANALYSIS_CONFIGURATION` in `src/core/onboarding.py`.

### Adding a Backend API Endpoint
1. Open [`src/api/server.py`](src/api/server.py).
2. Add your route handler under the FastAPI `app` instance using standard Pydantic models:
   ```python
   @app.get("/api/custom-endpoint")
   async def custom_endpoint(db: PostgresStorage = Depends(get_db)):
       return {"status": "ok"}
   ```
3. Add corresponding unit tests in `tests/`.

### Modifying the Onboarding Workflow Generator
1. Open [`src/core/onboarding.py`](src/core/onboarding.py).
2. Edit `generate_expected_workflow(orchestrator_ref)`. Ensure all `workflow_dispatch` inputs match the input schema accepted by `.github/workflows/reusable-analysis.yml` and `.github/workflows/reusable-finding-recheck.yml`.
3. Update `_analyze_yaml_jobs()` or `classify_workflow_content()` if structural classification rules change.
4. Run `python -m pytest tests/test_onboarding_migration.py -v` to ensure parity.

---

## 7. Troubleshooting and Known Technical Limitations

### 7.1. Snyk CLI Executable Missing

**Symptom:** The Snyk analysis tool reports an `ERROR` status with a message such as `snyk executable not found`.

**Cause:** The Snyk CLI is not installed or is not available on the `PATH` of the environment running the analysis.

**Resolution:**

1. Install Node.js and npm if they are not already available.

2. Install the Snyk CLI in the analysis environment:

   ```bash
   npm install -g snyk
   ```

3. Verify that the executable is accessible:

   ```bash
   snyk --version
   ```

4. Confirm that the environment's `PATH` includes the location where npm installs global executables.

For GitHub Actions, ensure the CLI is installed in the workflow runner before the Snyk adapter executes. Installing it on a developer's local machine does not make it available to a remote runner.

### 7.2. Node.js Dependency Resolution in Python Tests

**Affected components:**

* `src/adapters/extract_ui_context.js`
* `src/compliance/js_ast_extractor.js`

These JavaScript AST extractors depend on Node.js packages available through `node_modules`.

**Symptoms:** Tests or analysis operations involving JavaScript extraction fail with errors such as `Cannot find module`, even though Python dependencies are installed.

**Resolution:**

1. Verify that Node.js and npm are installed in the environment running the tests or analysis.
2. Ensure the required JavaScript dependencies are installed and available in the location expected by the extractors.
3. Run the relevant commands from the repository's working environment and inspect the extractor's module-resolution paths if dependencies cannot be found.
4. If the extractor runs from a copied or temporary location, verify how it resolves dependencies. Where appropriate, configure `NODE_PATH` to include the directory containing the required packages.

For example, in a compatible shell:

```bash
export NODE_PATH="/path/to/node_modules"
```

Replace `/path/to/node_modules` with the actual dependency directory. On Windows, use the equivalent environment-variable syntax for the shell in use.

**Note:** The dependency directory must be available in the execution environment; tracking `node_modules` in Git is not a universal requirement or a substitute for correct dependency installation and module resolution.

### 7.3. Single-File Limitation of Targeted Rechecks

**Limitation:** Targeted rechecks are designed to re-evaluate findings associated with an individual file. They do not support every analysis tool or finding type.

In particular:

* **Dependency vulnerability scans:** Tools such as Snyk may require dependency manifests, lockfiles, and broader project context.
* **Multi-file analysis:** Findings that depend on interactions between multiple files cannot always be reliably revalidated by scanning a single file.

These cases are explicitly marked as unsupported during targeted rechecks when the requested finding or tool requires broader analysis.

**Recommended approach:** Run a full repository analysis for dependency vulnerabilities, multi-file findings, or other cases that require project-wide context. Use targeted rechecks for supported findings where the relevant file provides sufficient context.
