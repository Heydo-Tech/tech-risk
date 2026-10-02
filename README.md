# Unified Repo Analysis Orchestrator

A unified Python orchestrator that runs code analysis, security, quality, and testing tools against a Git repository and produces a single normalized report (JSON and CSV).

## Features
- Clones target repository securely into a temporary directory.
- Runs a configurable suite of tools: Ruff, Bandit, Semgrep, Pip-audit, Mypy, Pytest (with coverage), and Import-Linter.
- Normalizes findings across all tools into a consistent format.
- Deduplicates overlapping findings across tools to reduce noise.
- Explicitly handles tool statuses (`COMPLETED`, `SKIPPED`, `ERROR`) to ensure `PASSED` means 100% clean.
- Outputs detailed JSON and summary-inclusive CSV reports.

## Supported Tools

### Python Ecosystem
- **Ruff**: Linting and code quality
- **Bandit**: Security analysis (SAST)
- **Pip-audit**: Dependency vulnerabilities
- **Mypy**: Static type checking
- **Pytest**: Unit testing and coverage
- **Import-Linter**: Architecture and dependency rules
- **Semgrep**: Advanced SAST across languages

### JS/TS/Node/React Ecosystem
- **Snyk Open Source**: Dependency vulnerabilities. Requires `snyk` CLI installed and authenticated (`snyk auth`). Handles multiple package manifests.
- **OWASP dep-scan**: Dependency vulnerabilities mapping to CVEs/GHSAs. Defaults to the lightweight `app` scope. Silent huge VDB downloads are prevented by default. Set `DEPSCAN_AUTO_DOWNLOAD=true` or run `depscan-vdb download --scope app` manually to fetch the database. Includes a configurable execution timeout (default 600s).
- **Dependency-Cruiser**: Architecture and forbidden dependency analysis. Requires `.dependency-cruiser.js` configuration.
- **SonarQube Community**: Code quality and SAST. Requires `sonar-scanner` and `sonar-project.properties` (or `SONAR_HOST_URL` env var).
- **React Doctor**: Code quality and best practices for React repositories. Automatically detects React via `package.json` or `.jsx`/`.tsx` files.
- **Semgrep**: Advanced SAST across languages.

*Note: The orchestrator automatically detects the ecosystem based on files (e.g. `package.json`, `.py`, `.jsx`) and gracefully skips tools that are not applicable to the repository. If a tool crashes or times out, it is isolated and the orchestrator continues with the remaining tools safely.*

## Setup

1. Install Python requirements:
   ```bash
   pip install -r requirements.txt
   ```

2. Make sure the tools you intend to use are available in your `PATH`.
   - JS tools can be installed globally via npm (e.g. `npm install -g snyk @owasp/dep-scan dependency-cruiser`).
   - SonarQube requires the `sonar-scanner` executable.
   - Snyk requires authentication via `snyk auth`.

## Usage

Run the orchestrator by passing the URL to a repository (or a local directory path):

```bash
python analyze_repo.py https://github.com/user/repo
```

### Options

- `--branch main` : Analyze a specific branch.
- `--tools ruff,bandit,pytest,snyk` : Selectively run a subset of tools.
- `--output json,csv` : Select output formats.
- `--persist` : Store `report.json` in PostgreSQL (requires `--database-url` or `DATABASE_URL`).

### Local PostgreSQL persistence

Reports can be stored outside the target repository as PostgreSQL `JSONB`. The
first run creates the `analysis_runs` table and indexes automatically:

```bash
set DATABASE_URL=postgresql://user:password@localhost:5432/repo_analysis
python analyze_repo.py . --repo-name Heydo-Tech/example --tools ruff --output json --persist
```

Each row keeps the complete report plus repository, commit SHA, branch, and
workflow run metadata. PostgreSQL support is optional; analysis continues to
work as before when `--persist` is not supplied.

## Adding a New Tool Adapter

1. Create a new file in `src/adapters/` (e.g., `newtool_adapter.py`).
2. Implement the `BaseAdapter` class.
3. Parse the tool's native output and convert it into `Finding` dataclasses.
4. Add the adapter to the `ALL_ADAPTERS` dictionary in `analyze_repo.py`.

```python
from src.adapters.base import BaseAdapter
from src.core.models import ToolResult, ToolStatus

class NewToolAdapter(BaseAdapter):
    @property
    def tool_name(self) -> str:
        return "new-tool"

    @property
    def categories(self) -> list:
        return ["security"]

    def run(self, repo_path: str) -> ToolResult:
        # Run tool via subprocess
        # Parse output
        # Return ToolResult
        pass
```

## GitHub Actions CI Integration

This repository acts as the central hub for the Repo Analysis Orchestrator. It exposes a **Reusable GitHub Actions workflow** (`.github/workflows/reusable-analysis.yml`).

### Calling the Reusable Workflow
You can integrate this orchestrator into any other repository without copying its code.

Create a workflow file in your target repository (e.g., `Custom-Assembler/.github/workflows/code-analysis.yml`):

```yaml
name: Code Analysis

on:
  push:
    branches: [ "**" ]
  pull_request:
    branches: [ "**" ]
  workflow_dispatch:

jobs:
  analyze:
    uses: manasvipaweria/tech-risk/.github/workflows/reusable-analysis.yml@main
```

### What happens during execution?
1. **Target repository**: GitHub Actions checks out the target repository (e.g., `Custom-Assembler`).
2. **Central tech-risk workflow**: It fetches this central orchestrator.
3. **V2 analysis**: It runs the orchestrator against the target repository. The `code_context` will be safely extracted from the target repository's files.
4. **JSON + CSV**: It generates the reports with the target repository's identifier (e.g., `manasvipaweria/Custom-Assembler`).
5. **Artifact**: The reports are uploaded as the `repo-analysis-report` artifact to the target repository's workflow run.

### AI Analysis Stage

The orchestrator now supports an AI-powered post-processing stage to validate findings, reduce false positives, and provide concrete remediation suggestions. 

To run the AI analysis, use the `--run-ai` flag:

```bash
python analyze_repo.py https://github.com/user/repo --run-ai
```

#### How it works:
1. **Report Processor**: After the standard scanners generate `report.json`, the Report Processor validates finding counts and extracts only the relevant data needed for AI reasoning into a smaller `ai_input.json` file, shedding unnecessary tool metadata.
2. **Secret Redaction**: Before `ai_input.json` is generated, a mandatory secret redaction layer scrubs the `message` and `code_context` fields for sensitive credentials (API keys, JWTs, cloud credentials, etc.), replacing them with `[REDACTED_SECRET]`.
3. **AI Adapter**: The generic AI adapter reads `ai_input.json`, loads the versioned skill instructions (`src/ai/skills/ai_analysis_v1.txt`), and queries the configured AI provider.
4. **AI Enriched Report**: The adapter writes the structural AI response back into the original `report.json`, appending `ai_fields` to the corresponding findings. 

#### AI Configuration
The orchestrator uses a provider-agnostic architecture. Set the following environment variables:
- `AI_PROVIDER`: The provider to use (`mock`, `openai`, `gemini`). Defaults to `openai`.
- `AI_BATCH_SIZE`: Controls how many findings are analyzed initially (defaults to `5`).
- `AI_MAX_OUTPUT_TOKENS`: Maximum tokens the model may generate (defaults to `500`).

**OpenAI Provider (`AI_PROVIDER=openai`)**
- `AI_API_KEY`: Your OpenAI API key.
- `AI_API_URL`: The API endpoint (defaults to OpenAI chat completions).
- `AI_MODEL`: The model to use (defaults to `gpt-4-turbo-preview`).

**Gemini Provider (`AI_PROVIDER=gemini`)**
- `GEMINI_API_KEY`: Your Gemini API key.
- `GEMINI_MODEL`: The model to use (defaults to `gemini-3.5-flash`).

**Mock Provider (`AI_PROVIDER=mock`)**
No credentials required. Fast, deterministic, completely local response. The output explicitly labels itself as mock and does not represent a real security assessment.

If credentials are required but missing, the AI stage gracefully skips. 

#### Token Estimation (Dry Run)
You can estimate token usage without consuming API quota or making network calls:
```bash
python -m src.ai.ai_adapter ai_input.json report.json --estimate-tokens
```
This local calculation evaluates your skill and input size (using approximation heuristics where exact provider tokenizers are not locally available).

### Adding a new AI Provider
To add a new AI provider, create a new class in `src/ai/providers/` extending `AIProvider`. Implement the `analyze` and `estimate_tokens` methods, then register it in `AIAdapter.__init__`. The core logic (`report_processor.py` and finding schemas) requires zero modification.

### Future Enhancements
The following features are intentionally deferred to a later phase and are not yet implemented:
- Automatic code fixes pushed back to the branch
- Historical / new-finding incremental analysis comparison
- Production/Merge blocking enforcement natively within GitHub branch protection
