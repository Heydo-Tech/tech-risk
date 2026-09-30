
import os
import base64
import csv
import hmac
import json
import io
import zipfile
import uuid
import re
import uvicorn
from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Any, List, Dict

from src.storage.postgres import (
    get_or_create_findings_lifecycle,
    get_finding_lifecycle,
    update_finding_lifecycle,
    _connect,
    initialize_schema,
)
from src.core.models import Finding
from src.core.recheck import (
    SUPPORTED_RECHECK_TOOLS,
    build_recheck_dispatch,
    normalize_github_repository,
)

app = FastAPI(title="Repo Analysis API - Phase 2")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/repo_analysis")
# Demo data must never look like repository data in a normal run.  It remains
# available only when a developer deliberately opts in.
ALLOW_MOCK_FALLBACK = os.environ.get("ALLOW_MOCK_FALLBACK", "false").lower() == "true"

class RecheckRequest(BaseModel):
    repository: Optional[str] = None
    owner: Optional[str] = None
    name: Optional[str] = None
    branch: Optional[str] = None
    commit_sha: Optional[str] = None
    tool: str
    rule_id: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None
    line_end: Optional[int] = None


class RecheckResultRequest(BaseModel):
    repository: str
    tool: str
    rule_id: str
    status: str
    message: Optional[str] = None
    workflow_run_id: Optional[str] = None
    attempt_id: Optional[str] = None
    commit_sha: Optional[str] = None


def _get_mock_report_summary(run_id="mock-1"):
    return {
        "id": run_id,
        "repository": "Heydo-Tech/repo-orchestrator",
        "branch": "main",
        "commit_sha": "abc123mock",
        "workflow_run_id": "wf-mock",
        "status": "COMPLETED",
        "started_at": "2026-09-23T10:00:00Z",
        "completed_at": "2026-09-23T10:05:00Z",
        "total_findings": 2
    }

def _get_mock_report_detail(run_id="mock-1"):
    summary = _get_mock_report_summary(run_id)
    metadata = dict(summary)
    summary["report"] = {
        "metadata": metadata,
        "summary": {
            "security": {"status": "COMPLETED", "count": 1},
            "dependency_security": {"status": "COMPLETED", "count": 1}
        },
        "findings": _mock_findings()
    }
    return summary

def _mock_findings():
    return [
        {
            "finding_id": "semgrep-sql-001",
            "title": "SQL Injection",
            "category": "security",
            "severity": "HIGH",
            "tool": "semgrep",
            "rule_id": "python.django.security.injection.sql-injection",
            "location": {
                "path": "src/auth/login.py",
                "start_line": 84,
                "code_snippet": "82 | const user = ...\n83 | const query = ...\n84 | db.query(userInput)\n85 | ..."
            },
            "description": "Detected unescaped user input in SQL query.",
            "remediation": "Use parameterized queries or an ORM.",
            "lifecycle": {"status": "OPEN", "history": []}
        },
        {
            "finding_id": "snyk-fast-uri-002",
            "title": "Vulnerable Dependency",
            "category": "dependency_security",
            "severity": "CRITICAL",
            "tool": "snyk",
            "rule_id": "SNYK-JS-FASTURI-315",
            "location": {
                "path": "package.json",
                "start_line": 14
            },
            "description": "fast-uri version 3.1.5 has a known vulnerability.",
            "remediation": "Upgrade to a non-vulnerable supported version like 3.1.6.",
            "lifecycle": {"status": "OPEN", "history": []}
        }
    ]

def _sanitize_report_for_download(report: dict) -> dict:
    # Remove any keys that look like secrets from metadata
    if "metadata" in report:
        meta = report["metadata"]
        keys_to_remove = []
        for k in meta.keys():
            if "TOKEN" in k.upper() or "KEY" in k.upper() or "SECRET" in k.upper() or "PASSWORD" in k.upper():
                keys_to_remove.append(k)
        for k in keys_to_remove:
            meta[k] = "[REDACTED]"
    return report

def _generate_csv(report: dict) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Headers
    writer.writerow([
        "finding_id", "repository", "tool", "category", "severity", 
        "priority", "rule_id", "file", "line", "message", "status"
    ])
    
    findings = report.get("findings", [])
    metadata = report.get("metadata") or {}
    repo_name = metadata.get("repository") or report.get("repo") or "unknown"
    
    for f in findings:
        writer.writerow([
            f.get("finding_id", ""),
            repo_name,
            f.get("tool", ""),
            f.get("category", ""),
            f.get("severity", ""),
            f.get("priority", ""),
            f.get("rule_id", ""),
            f.get("location", {}).get("path", "") if isinstance(f.get("location"), dict) else "",
            f.get("location", {}).get("start_line", "") if isinstance(f.get("location"), dict) else "",
            f.get("title", f.get("message", "")),
            (f.get("lifecycle") or {}).get("status", "OPEN")
        ])
        
    return output.getvalue()


@app.get("/api/reports")
def list_reports(repo: Optional[str] = None):
    try:
        initialize_schema(DATABASE_URL)
        with _connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                if repo:
                    cur.execute("SELECT id, repository, branch, commit_sha, workflow_run_id, status, started_at, completed_at, report FROM analysis_runs WHERE repository = %s ORDER BY id DESC", (repo,))
                else:
                    cur.execute("SELECT id, repository, branch, commit_sha, workflow_run_id, status, started_at, completed_at, report FROM analysis_runs ORDER BY id DESC")
                
                rows = cur.fetchall()
                if not rows and ALLOW_MOCK_FALLBACK:
                    return {"data_source": "mock", "reports": [_get_mock_report_summary("mock-1"), _get_mock_report_summary("mock-2")]}
                
                reports = []
                for row in rows:
                    r_id, r_repo, branch, commit, wf_id, status, started_at, completed_at, report_data = row
                    report_data = report_data if isinstance(report_data, dict) else {}
                    findings_count = len(report_data.get("findings", []))
                    reports.append({
                        "id": r_id,
                        "repository": r_repo,
                        "branch": branch,
                        "commit_sha": commit,
                        "workflow_run_id": wf_id,
                        "status": status,
                        "started_at": started_at.isoformat() if started_at else None,
                        "completed_at": completed_at.isoformat() if completed_at else None,
                        "total_findings": findings_count
                    })
                return {"data_source": "postgres", "reports": reports}
    except Exception as e:
        print(f"[reports] PostgreSQL list failed repository={repo or 'all'} error={e}")
        # Never replace a real, completed fallback report with demo findings.
        # This path is primarily useful during local recovery; production is
        # expected to supply a working DATABASE_URL.
        from src.storage.postgres import _in_memory_runs
        memory_reports = []
        for memory_run in _in_memory_runs.values():
            if repo and memory_run.get("repository") != repo:
                continue
            report_data = memory_run.get("report")
            memory_reports.append({
                "id": memory_run.get("id"),
                "repository": memory_run.get("repository"),
                "branch": memory_run.get("branch"),
                "commit_sha": memory_run.get("commit_sha"),
                "workflow_run_id": memory_run.get("workflow_run_id"),
                "status": memory_run.get("status"),
                "started_at": memory_run.get("started_at"),
                "completed_at": memory_run.get("completed_at"),
                "total_findings": len(report_data.get("findings", [])) if isinstance(report_data, dict) else 0,
            })
        if memory_reports:
            memory_reports.sort(key=lambda item: int(item.get("id") or 0), reverse=True)
            return {"data_source": "memory_fallback", "reports": memory_reports}
        if ALLOW_MOCK_FALLBACK:
            return {"data_source": "mock", "reports": [_get_mock_report_summary("mock-1"), _get_mock_report_summary("mock-2")]}
        raise HTTPException(status_code=500, detail="Database connection failed")

@app.get("/api/reports/compare")
def compare_reports(base: str, current: str):
    # Fetch base
    base_report = _fetch_full_report(base)
    current_report = _fetch_full_report(current)
    
    if not base_report or not current_report:
        raise HTTPException(status_code=404, detail="One or both reports not found")
        
    base_findings = {f["finding_id"]: f for f in base_report.get("report", {}).get("findings", [])}
    current_findings = {f["finding_id"]: f for f in current_report.get("report", {}).get("findings", [])}
    
    base_keys = set(base_findings.keys())
    current_keys = set(current_findings.keys())
    
    new_keys = current_keys - base_keys
    removed_keys = base_keys - current_keys
    unchanged_keys = base_keys & current_keys
    
    return {
        "data_source": base_report.get("data_source", "unknown"),
        "comparison": {
            "base_id": base,
            "current_id": current,
            "total_base": len(base_keys),
            "total_current": len(current_keys),
            "difference": len(current_keys) - len(base_keys),
            "new_findings": len(new_keys),
            "no_longer_detected": len(removed_keys),
            "unchanged": len(unchanged_keys)
        }
    }


def _fetch_full_report(run_id: str) -> Optional[dict]:
    if str(run_id).startswith("mock-") and ALLOW_MOCK_FALLBACK:
        return {"data_source": "mock", **_get_mock_report_detail(run_id)}
        
    try:
        initialize_schema(DATABASE_URL)
        row = None
        with _connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, repository, branch, commit_sha, workflow_run_id, status, started_at, completed_at, report FROM analysis_runs WHERE id = %s", (run_id,))
                row = cur.fetchone()
        # The report SELECT transaction must be closed before the lifecycle
        # helper opens its own connection and performs schema-safe inserts.
        # Keeping it open creates a self-inflicted relation lock.
        if row:
            r_id, r_repo, branch, commit, wf_id, status, started_at, completed_at, report_data = row
            report_data = dict(report_data) if isinstance(report_data, dict) else {}
            raw_findings = report_data.get("findings", [])
            lifecycle_by_id = get_or_create_findings_lifecycle(
                [finding.get("finding_id") for finding in raw_findings],
                DATABASE_URL,
            )
            enriched_findings = []
            for finding in raw_findings:
                enriched = dict(finding)
                enriched["lifecycle"] = lifecycle_by_id.get(
                    finding.get("finding_id"),
                    {"status": finding.get("status", "OPEN"), "history": []},
                )
                enriched_findings.append(enriched)

            report_data["findings"] = enriched_findings

            return {
                "data_source": "postgres",
                "id": r_id,
                "repository": r_repo,
                "branch": branch,
                "commit_sha": commit,
                "workflow_run_id": wf_id,
                "status": status,
                "started_at": started_at.isoformat() if started_at else None,
                "completed_at": completed_at.isoformat() if completed_at else None,
                "total_findings": len(enriched_findings),
                "report": report_data
            }
    except Exception as e:
        print(f"DB error fetching report {run_id}:", e)

    # Fallback to memory runs if DB unavailable or mock fallback
    from src.storage.postgres import _in_memory_runs
    try:
        r_int = int(run_id)
        if r_int in _in_memory_runs:
            mem = _in_memory_runs[r_int]
            rep = mem.get("report", {})
            return {
                "data_source": "memory_fallback",
                "id": mem["id"],
                "repository": mem["repository"],
                "branch": mem.get("branch"),
                "commit_sha": mem.get("commit_sha"),
                "workflow_run_id": mem.get("workflow_run_id"),
                "status": mem.get("status"),
                "started_at": mem.get("started_at"),
                "completed_at": mem.get("completed_at"),
                "total_findings": len(rep.get("findings", [])),
                "report": rep
            }
    except Exception:
        pass

    return None


@app.get("/api/reports/{run_id}")
def get_report(run_id: str):
    data = _fetch_full_report(run_id)
    if not data:
        raise HTTPException(status_code=404, detail="Report not found")
    return data

@app.get("/api/reports/{run_id}/download/json")
def download_report_json(run_id: str):
    data = _fetch_full_report(run_id)
    if not data:
        raise HTTPException(status_code=404, detail="Report not found")
        
    report = data.get("report", {})
    sanitized = _sanitize_report_for_download(report)
    
    repo_name = data.get("repository", "repo").replace("/", "-")
    date_str = (data.get("completed_at") or "2026-09-24")[:10]
    filename = f"{repo_name}-{date_str}-report.json"
    
    return JSONResponse(
        content=sanitized,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@app.get("/api/reports/{run_id}/download/csv")
def download_report_csv(run_id: str):
    data = _fetch_full_report(run_id)
    if not data:
        raise HTTPException(status_code=404, detail="Report not found")
        
    report = data.get("report", {})
    csv_content = _generate_csv(report)
    
    repo_name = data.get("repository", "repo").replace("/", "-")
    date_str = (data.get("completed_at") or "2026-09-24")[:10]
    filename = f"{repo_name}-{date_str}-report.csv"
    
    return StreamingResponse(
        iter([csv_content.encode("utf-8")]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@app.get("/api/findings")
def get_findings(repo: str):
    # Use the newest COMPLETED run containing a real report.  A newer RUNNING
    # row must not hide the last usable scan.
    res = list_reports(repo)
    reports = res.get("reports", [])
    completed = [
        report for report in reports
        if report.get("status") == "COMPLETED" and int(report.get("total_findings") or 0) >= 0
    ]
    full = None
    for report in completed:
        candidate = _fetch_full_report(str(report["id"]))
        if candidate and isinstance(candidate.get("report"), dict) and "findings" in candidate["report"]:
            full = candidate
            break
    if not full:
        if ALLOW_MOCK_FALLBACK and not reports:
            return {"data_source": "mock", "repository": repo, "run_id": "mock-1", "findings": _mock_findings()}
        return {"data_source": res.get("data_source", "postgres"), "repository": repo, "run_id": None, "findings": []}

    report = full.get("report", {})
    normalized_tools, normalized_findings = _normalize_analysis_tools(report)
    return {
        "data_source": full.get("data_source"),
        "repository": repo,
        "run_id": full.get("id"),
        "branch": full.get("branch"),
        "commit_sha": full.get("commit_sha"),
        "tools": normalized_tools,
        "findings": normalized_findings,
    }


_TOOL_LABELS = {
    "ruff": "Ruff",
    "bandit": "Bandit",
    "semgrep": "Semgrep",
    "pip-audit": "Pip Audit",
    "mypy": "Mypy",
    "pytest": "Pytest",
    "import-linter": "Import Linter",
    "snyk": "Snyk",
    "dep-scan": "Dependency Scan",
    "dependency-cruiser": "Dependency Cruiser",
    "sonarqube": "SonarQube",
    "react-doctor": "React Doctor",
    "codex-security": "Codex Security",
    "codex-architecture": "Codex Architecture",
    "apnimandi-design": "ApniMandi Design",
    "deslint": "Deslint",
}

# These identifiers are emitted by the orchestrator's deterministic
# post-processing stage.  They are not independently configured adapters and
# therefore must not appear as separate user-facing tools.
_COMPLIANCE_FINDING_SOURCES = {
    "data-flow-extractor",
    "dpdp-engine",
    "spdi-engine",
    "cra-engine",
    "cert-in-engine",
    "repo-orchestrator-trai-dlt-engine",
    "security_evidence",
}
_COMPLIANCE_RULE_PREFIXES = ("TCPA-", "EPRIVACY-")


def _tool_label(tool_id: str) -> str:
    return _TOOL_LABELS.get(
        tool_id,
        " ".join(part.capitalize() for part in tool_id.replace("_", "-").split("-") if part),
    )


def _normalize_analysis_tools(report: dict) -> tuple[list[dict], list[dict]]:
    """Build user-facing tools from report execution metadata.

    ``summary.*.tools`` is authoritative for configured/executed adapters and
    their execution state.  ``detected_by`` is used only to attribute real
    findings to those tools, never to invent the executed-tool list.
    """
    tools: dict[str, dict] = {}
    status_priority = {"COMPLETED": 1, "NOT_APPLICABLE": 2, "SKIPPED": 2, "ERROR": 3}

    for category in (report.get("summary") or {}).values():
        if not isinstance(category, dict):
            continue
        for tool_id, metadata in (category.get("tools") or {}).items():
            if not isinstance(metadata, dict):
                metadata = {}
            execution_status = str(metadata.get("status") or "SKIPPED").upper()
            existing = tools.get(tool_id)
            if not existing:
                tools[tool_id] = {
                    "id": tool_id,
                    "label": _tool_label(tool_id),
                    "execution_status": execution_status,
                    "error_message": metadata.get("error_message"),
                    "finding_count": 0,
                }
            elif status_priority.get(execution_status, 2) > status_priority.get(existing["execution_status"], 2):
                existing["execution_status"] = execution_status
                existing["error_message"] = metadata.get("error_message")

    normalized_findings = []
    for raw_finding in report.get("findings") or []:
        finding = dict(raw_finding)
        sources = finding.get("detected_by") or ([finding.get("tool")] if finding.get("tool") else [])
        analysis_tools = []
        unknown_sources = []
        has_compliance_source = str(finding.get("rule_id") or "").upper().startswith(_COMPLIANCE_RULE_PREFIXES)
        for source in filter(None, sources):
            if source in tools:
                analysis_tools.append(source)
            elif source in _COMPLIANCE_FINDING_SOURCES:
                has_compliance_source = True
            else:
                unknown_sources.append(source)

        if has_compliance_source:
            compliance_id = "orchestrator-compliance"
            tools.setdefault(compliance_id, {
                "id": compliance_id,
                "label": "Compliance analysis",
                "execution_status": "COMPLETED",
                "error_message": None,
                "finding_count": 0,
            })
            analysis_tools.append(compliance_id)

        if unknown_sources or not analysis_tools:
            other_id = "other-analysis"
            tools.setdefault(other_id, {
                "id": other_id,
                "label": "Other analysis",
                "execution_status": "COMPLETED",
                "error_message": None,
                "finding_count": 0,
            })
            analysis_tools.append(other_id)

        analysis_tools = list(dict.fromkeys(analysis_tools))
        finding["analysis_tools"] = analysis_tools
        if unknown_sources:
            finding["unmapped_sources"] = list(dict.fromkeys(unknown_sources))
        normalized_findings.append(finding)
        for tool_id in analysis_tools:
            tools[tool_id]["finding_count"] += 1

    for tool in tools.values():
        execution_status = tool["execution_status"]
        if execution_status == "ERROR":
            tool["status"] = "FAILED"
        elif execution_status in {"SKIPPED", "NOT_APPLICABLE"}:
            tool["status"] = "SKIPPED"
        elif tool["finding_count"]:
            tool["status"] = "FINDINGS"
        else:
            tool["status"] = "CLEAN"

    status_order = {"FINDINGS": 0, "CLEAN": 1, "FAILED": 2, "SKIPPED": 2}
    normalized_tools = sorted(
        tools.values(),
        key=lambda tool: (status_order.get(tool["status"], 3), -tool["finding_count"], tool["label"].lower()),
    )
    return normalized_tools, normalized_findings

def _finding_for_recheck(repository: str, finding_id: str) -> Optional[dict]:
    """Find a real persisted finding without fetching repository contents."""
    reports_result = list_reports(repo=repository)
    for report_summary in reports_result.get("reports", []):
        if report_summary.get("status") != "COMPLETED":
            continue
        full_report = _fetch_full_report(str(report_summary["id"]))
        for finding in (full_report or {}).get("report", {}).get("findings", []):
            if str(finding.get("finding_id")) == str(finding_id):
                return finding
    return None


def _finding_supports_recheck_tool(finding: dict, tool: str) -> bool:
    """Do not allow a client to recheck an arbitrary tool against a finding."""
    sources = finding.get("detected_by") or finding.get("tool") or []
    if isinstance(sources, str):
        sources = [sources]
    normalized_sources = {str(source).strip().lower() for source in sources if source}
    return tool in normalized_sources


def _github_recheck_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Repo-Analysis-Orchestrator",
    }


@app.post("/api/findings/{finding_id}/recheck")
def recheck_finding(finding_id: str, req: RecheckRequest):
    """Dispatch a strict, targeted recheck to the selected repository's runner.

    This endpoint intentionally never clones, downloads, or executes target code.
    """
    try:
        attempt_id = str(uuid.uuid4())
        identity, dispatch_inputs = build_recheck_dispatch(finding_id, req, attempt_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    finding = _finding_for_recheck(identity["full_name"], finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding was not found in a completed report for this repository")
    if not _finding_supports_recheck_tool(finding, dispatch_inputs["recheck_tool"]):
        raise HTTPException(status_code=400, detail="Requested tool does not match the selected finding")
    if str(finding.get("rule_id") or "") != dispatch_inputs["recheck_rule_id"]:
        raise HTTPException(status_code=400, detail="Requested rule ID does not match the selected finding")

    lifecycle = get_finding_lifecycle(finding_id, DATABASE_URL)
    if lifecycle.get("status") == "RECHECKING":
        return {
            "finding_id": finding_id,
            "repository": identity["full_name"],
            "status": "RECHECKING",
            "already_rechecking": True,
        }

    connection = get_github_connection(DATABASE_URL)
    if not connection:
        raise HTTPException(status_code=401, detail="GitHub not connected")
    headers = _github_recheck_headers(connection["token"])

    # Resolve the workflow ref from GitHub rather than trusting a client branch.
    repo_response = requests.get(
        f"https://api.github.com/repos/{identity['full_name']}", headers=headers, timeout=15
    )
    if repo_response.status_code != 200:
        raise HTTPException(
            status_code=repo_response.status_code if repo_response.status_code in (403, 404) else 502,
            detail={"message": "Selected repository is not accessible for targeted recheck.", **_github_api_error_context(repo_response)},
        )
    default_branch = repo_response.json().get("default_branch") or "main"

    workflow_url = (
        f"https://api.github.com/repos/{identity['full_name']}/contents/"
        f".github/workflows/{WORKFLOW_FILE_NAME}?ref={default_branch}"
    )
    workflow_response = requests.get(workflow_url, headers=headers, timeout=15)
    if workflow_response.status_code != 200:
        raise HTTPException(
            status_code=400 if workflow_response.status_code == 404 else 502,
            detail="The repository workflow is unavailable. Update the onboarding workflow before rechecking findings.",
        )
    try:
        workflow_text = base64.b64decode(workflow_response.json().get("content", "")).decode("utf-8")
    except Exception:
        raise HTTPException(status_code=400, detail="The repository workflow could not be read for targeted recheck.")
    if "workflow_dispatch" not in workflow_text or "recheck_finding_id" not in workflow_text:
        raise HTTPException(
            status_code=400,
            detail="The repository workflow does not support targeted recheck. Update the onboarding workflow first.",
        )

    update_finding_lifecycle(
        finding_id=finding_id,
        database_url=DATABASE_URL,
        status="RECHECKING",
        commit_sha=dispatch_inputs["recheck_commit_sha"] or None,
        tool=dispatch_inputs["recheck_tool"],
        scope="file" if dispatch_inputs["recheck_file_path"] else "project",
        message="Targeted GitHub Actions recheck dispatched",
        recheck_attempt_id=attempt_id,
    )
    dispatch_response = requests.post(
        f"https://api.github.com/repos/{identity['full_name']}/actions/workflows/{WORKFLOW_FILE_NAME}/dispatches",
        headers=headers,
        json={"ref": default_branch, "inputs": dispatch_inputs},
        timeout=15,
    )
    if dispatch_response.status_code != 204:
        update_finding_lifecycle(
            finding_id=finding_id,
            database_url=DATABASE_URL,
            status="OPEN",
            tool=dispatch_inputs["recheck_tool"],
            scope="file" if dispatch_inputs["recheck_file_path"] else "project",
            message=f"Targeted GitHub Actions recheck could not be dispatched (HTTP {dispatch_response.status_code})",
            recheck_attempt_id=attempt_id,
        )
        raise HTTPException(
            status_code=dispatch_response.status_code if dispatch_response.status_code in (403, 404) else 502,
            detail={"message": "GitHub Actions targeted recheck dispatch failed.", **_github_api_error_context(dispatch_response)},
        )
    return {
        "finding_id": finding_id,
        "repository": identity["full_name"],
        "tool": dispatch_inputs["recheck_tool"],
        "status": "RECHECKING",
        "attempt_id": attempt_id,
    }


import requests
from src.storage.postgres import (
    get_github_connection, save_github_connection, delete_github_connection,
    get_managed_repos, get_repo_onboarding, set_managed_repo
)

class ConnectRequest(BaseModel):
    token: str

class SelectRepoRequest(BaseModel):
    full_name: str
    owner: str
    name: str
    selected: bool


class BulkOnboardRepository(BaseModel):
    owner: str
    name: str


class BulkOnboardRequest(BaseModel):
    repositories: List[BulkOnboardRepository]


class RepositorySecretRequest(BaseModel):
    secret_value: str
    replace_existing: bool = False
    replace_repositories: List[str] = []

SAFE_GITHUB_RESPONSE_HEADERS = (
    "X-Accepted-GitHub-Permissions",
    "X-OAuth-Scopes",
    "X-Accepted-OAuth-Scopes",
    "X-GitHub-Request-Id",
    "X-RateLimit-Remaining",
    "X-RateLimit-Reset",
)

WORKFLOW_FILE_NAME = "code-analysis.yml"
GITHUB_SECRET_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ONBOARDED_SECRET_STATUSES = frozenset({"UP_TO_DATE", "DRIFT"})

def _redact_secret(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _redact_secret(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_secret(v) for v in value]
    if isinstance(value, str):
        redacted = value
        for prefix in ("ghp_", "github_pat_", "gho_", "ghu_", "ghs_", "ghr_"):
            start = redacted.find(prefix)
            while start != -1:
                end = start
                while end < len(redacted) and not redacted[end].isspace():
                    end += 1
                redacted = redacted[:start] + "[REDACTED_GITHUB_TOKEN]" + redacted[end:]
                start = redacted.find(prefix)
        return redacted
    return value

def _safe_response_body(response: requests.Response) -> Dict[str, Any]:
    try:
        body = response.json()
    except Exception:
        body = {"message": response.text}
    if not isinstance(body, dict):
        body = {"body": body}
    return _redact_secret(body)

def _safe_response_headers(response: requests.Response) -> Dict[str, str]:
    return {
        header: response.headers.get(header)
        for header in SAFE_GITHUB_RESPONSE_HEADERS
        if response.headers.get(header)
    }

def _github_api_error_context(response: requests.Response) -> Dict[str, Any]:
    return {
        "github_status": response.status_code,
        "github_response": _safe_response_body(response),
        "github_headers": _safe_response_headers(response),
    }

def _github_error_message(response: requests.Response) -> str:
    body = _safe_response_body(response)
    return str(body.get("message") or body.get("body") or "No message provided by GitHub")


def _normalize_github_secret_name(secret_name: str) -> str:
    """Validate and normalize a repository Actions secret name before GitHub calls."""
    normalized = str(secret_name or "").strip().upper()
    if not GITHUB_SECRET_NAME_RE.fullmatch(normalized):
        raise ValueError("Secret names may contain only letters, numbers, and underscores, and cannot start with a number")
    if normalized.startswith("GITHUB_"):
        raise ValueError("Secret names cannot start with GITHUB_")
    return normalized


def _github_secret_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Repo-Analysis-Orchestrator",
    }


def _encrypt_github_actions_secret(public_key: str, secret_value: str) -> str:
    """Return GitHub's required LibSodium sealed-box representation of a secret.

    The plaintext is only held in the request and this function's local memory.
    """
    try:
        from nacl.public import PublicKey, SealedBox
        key = PublicKey(base64.b64decode(public_key))
        encrypted = SealedBox(key).encrypt(secret_value.encode("utf-8"))
        return base64.b64encode(encrypted).decode("ascii")
    except Exception as exc:
        raise RuntimeError("Could not encrypt the repository secret") from exc


def _safe_secret_error(response: requests.Response, secret_value: str) -> str:
    """Return a diagnostic that cannot echo plaintext supplied by the client."""
    message = _github_error_message(response)
    if secret_value:
        message = message.replace(secret_value, "[REDACTED]")
    return f"GitHub returned {response.status_code}: {message}"


def _configure_repository_secret(identity: Dict[str, str], secret_name: str, secret_value: str, token: str) -> Dict[str, str]:
    """Set one repository Actions secret; callers deliberately continue after failures."""
    base_url = f"https://api.github.com/repos/{identity['full_name']}/actions/secrets"
    headers = _github_secret_headers(token)
    try:
        key_response = requests.get(f"{base_url}/public-key", headers=headers, timeout=15)
    except requests.RequestException:
        return {"repository": identity["full_name"], "status": "rejected", "reason": "GitHub public-key request failed"}
    if key_response.status_code != 200:
        return {
            "repository": identity["full_name"],
            "status": "rejected",
            "reason": _safe_secret_error(key_response, secret_value),
        }
    try:
        public_key_data = key_response.json()
        encrypted_value = _encrypt_github_actions_secret(public_key_data["key"], secret_value)
        key_id = str(public_key_data["key_id"])
    except (KeyError, TypeError, ValueError, RuntimeError):
        return {"repository": identity["full_name"], "status": "rejected", "reason": "Could not encrypt the repository secret"}
    try:
        write_response = requests.put(
            f"{base_url}/{secret_name}",
            headers=headers,
            json={"encrypted_value": encrypted_value, "key_id": key_id},
            timeout=15,
        )
    except requests.RequestException:
        return {"repository": identity["full_name"], "status": "rejected", "reason": "GitHub secret update request failed"}
    if write_response.status_code not in (201, 204):
        return {
            "repository": identity["full_name"],
            "status": "rejected",
            "reason": _safe_secret_error(write_response, secret_value),
        }
    return {"repository": identity["full_name"], "status": "configured"}


def _repository_secret_metadata(
    identity: Dict[str, str], secret_name: str, token: str, secret_value: str = ""
) -> Dict[str, str]:
    """Read repository-secret metadata only; GitHub never exposes values."""
    try:
        response = requests.get(
            f"https://api.github.com/repos/{identity['full_name']}/actions/secrets/{secret_name}",
            headers=_github_secret_headers(token),
            timeout=15,
        )
    except requests.RequestException:
        return {"name": secret_name, "status": "INACCESSIBLE", "reason": "GitHub secret metadata request failed"}
    if response.status_code == 200:
        return {"name": secret_name, "status": "CONFIGURED"}
    if response.status_code == 404:
        return {"name": secret_name, "status": "MISSING"}
    reason = _github_error_message(response)
    if secret_value:
        reason = reason.replace(secret_value, "[REDACTED]")
    return {
        "name": secret_name,
        "status": "INACCESSIBLE",
        "reason": f"GitHub returned {response.status_code}: {reason}",
    }


def _safe_secret_metadata_result(identity: Dict[str, str], secret_name: str, token: str) -> Dict[str, str]:
    metadata = _repository_secret_metadata(identity, secret_name, token)
    return {"repository": identity["full_name"], **metadata}


def _required_repository_secret_statuses(identity: Dict[str, str], token: str, required_names: List[str]) -> List[Dict[str, str]]:
    return [_repository_secret_metadata(identity, secret_name, token) for secret_name in required_names]


def _onboarding_overall_status(workflow_status: str, secrets: List[Dict[str, str]]) -> str:
    if workflow_status == "ERROR":
        return "WORKFLOW_FAILED"
    if any(secret["status"] != "CONFIGURED" for secret in secrets):
        return "NEEDS_CONFIGURATION"
    return "READY" if workflow_status == "UP_TO_DATE" else "WORKFLOW_PENDING"


def _require_repository_secret_value(req: RepositorySecretRequest) -> str:
    value = str(req.secret_value or "")
    if not value:
        raise HTTPException(status_code=400, detail="Secret value is required")
    return value


def _onboarded_secret_repositories() -> List[Dict[str, str]]:
    """Resolve only repositories known to this system and already onboarded."""
    targets = []
    for managed in get_managed_repos(DATABASE_URL):
        onboarding = get_repo_onboarding(DATABASE_URL, managed["full_name"])
        if not onboarding or onboarding.get("status") not in ONBOARDED_SECRET_STATUSES:
            continue
        try:
            targets.append(normalize_github_repository(managed["full_name"]))
        except ValueError:
            continue
    return targets

def _validate_github_token(token: str):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    resp = requests.get("https://api.github.com/user", headers=headers, timeout=10)
    if resp.status_code == 200:
        data = resp.json()
        return True, data
    return False, {"error": "Invalid token or GitHub API error", "status": resp.status_code}

@app.get("/api/github/status")
def github_status():
    conn = get_github_connection(DATABASE_URL)
    if not conn:
        return {"connected": False}
    return {
        "connected": True,
        "username": conn["username"],
        "avatar_url": conn["avatar_url"],
        "token_hint": conn["token_hint"],
        "connected_at": conn["connected_at"]
    }

@app.post("/api/github/connect")
def github_connect(req: ConnectRequest):
    token = req.token.strip()
    if not token:
        raise HTTPException(status_code=400, detail="Token is required")
        
    valid, data = _validate_github_token(token)
    if not valid:
        raise HTTPException(status_code=401, detail="GitHub authentication failed. Please check your token.")
        
    hint = "****" + token[-4:] if len(token) > 4 else "****"
    
    # Save directly as plaintext because we don't have encryption setup yet (as permitted by instruction for MVP local dev, but documented)
    save_github_connection(DATABASE_URL, data.get("login", "unknown"), token, hint, data.get("avatar_url", ""))
    
    return {
        "connected": True,
        "username": data.get("login", "unknown"),
        "avatar_url": data.get("avatar_url", ""),
        "token_hint": hint
    }

@app.post("/api/github/update-token")
def github_update_token(req: ConnectRequest):
    # Same as connect, but semantic difference for UI
    return github_connect(req)

@app.post("/api/github/test")
def github_test():
    conn = get_github_connection(DATABASE_URL)
    if not conn:
        return {"status": "Connection failed", "details": "No token configured"}
        
    valid, data = _validate_github_token(conn["token"])
    if not valid:
        return {"status": "Connection failed", "details": "Token is invalid or expired"}
        
    return {"status": "Connected"}

@app.post("/api/github/disconnect")
def github_disconnect():
    delete_github_connection(DATABASE_URL)
    return {"success": True}

@app.get("/api/github/repos")
def github_repos():
    conn = get_github_connection(DATABASE_URL)
    if not conn:
        raise HTTPException(status_code=401, detail="Not connected to GitHub")
        
    headers = {
        "Authorization": f"Bearer {conn['token']}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    # Pagination placeholder (we just fetch 100 for MVP)
    resp = requests.get("https://api.github.com/user/repos?per_page=100&sort=updated", headers=headers, timeout=10)
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail="GitHub API error while fetching repositories")
        
    gh_repos = resp.json()
    
    # Merge with managed configuration
    managed = {r["full_name"]: r for r in get_managed_repos(DATABASE_URL)}
    
    results = []
    for r in gh_repos:
        perms = r.get("permissions", {})
        access_list = []
        if perms.get("push"):
            access_list.append("Write")
        elif perms.get("pull"):
            access_list.append("Read")
        
        access_str = "/".join(access_list) if access_list else "Access level unavailable"
        
        full_name = r["full_name"]
        
        results.append({
            "full_name": full_name,
            "name": r["name"],
            "owner": r["owner"]["login"],
            "private": r["private"],
            "default_branch": r["default_branch"],
            "html_url": r["html_url"],
            "access": access_str,
            "selected": managed.get(full_name, {}).get("selected", False),
            "updated_at": r.get("updated_at")
        })
        
    return {"repositories": results}

@app.post("/api/github/repos/select")
def github_select_repo(req: SelectRepoRequest):
    set_managed_repo(DATABASE_URL, req.full_name, req.owner, req.name, req.selected)
    return {"success": True, "selected": req.selected}


@app.put("/api/repositories/{owner}/{repo}/secrets/{secret_name}")
def put_repository_secret(owner: str, repo: str, secret_name: str, req: RepositorySecretRequest):
    """Create a missing secret or explicitly replace an existing one."""
    try:
        identity = normalize_github_repository(owner=owner, name=repo)
        normalized_name = _normalize_github_secret_name(secret_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    secret_value = _require_repository_secret_value(req)
    connection = get_github_connection(DATABASE_URL)
    if not connection:
        raise HTTPException(status_code=401, detail="GitHub not connected")
    metadata = _repository_secret_metadata(identity, normalized_name, connection["token"], secret_value)
    if metadata["status"] == "CONFIGURED" and not req.replace_existing:
        result = {"repository": identity["full_name"], "status": "kept"}
    elif metadata["status"] == "INACCESSIBLE":
        result = {"repository": identity["full_name"], "status": "rejected", "reason": metadata.get("reason", "Secret metadata is inaccessible")}
    else:
        result = _configure_repository_secret(identity, normalized_name, secret_value, connection["token"])
    return {
        "secret_name": normalized_name,
        "configured_count": int(result["status"] == "configured"),
        "kept_count": int(result["status"] == "kept"),
        "rejected_count": int(result["status"] == "rejected"),
        "results": [result],
    }


@app.put("/api/repositories/secrets/{secret_name}/apply")
def put_secret_for_all_onboarded_repositories(secret_name: str, req: RepositorySecretRequest):
    """Apply a secret independently to each system-known onboarded repository."""
    try:
        normalized_name = _normalize_github_secret_name(secret_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    secret_value = _require_repository_secret_value(req)
    connection = get_github_connection(DATABASE_URL)
    if not connection:
        raise HTTPException(status_code=401, detail="GitHub not connected")
    targets = _onboarded_secret_repositories()
    if not targets:
        raise HTTPException(status_code=400, detail="No onboarded repositories are available for this secret")
    explicit_replacements = set()
    try:
        explicit_replacements = {
            normalize_github_repository(repository).get("full_name")
            for repository in req.replace_repositories
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    results = []
    for identity in targets:
        metadata = _repository_secret_metadata(identity, normalized_name, connection["token"], secret_value)
        if metadata["status"] == "CONFIGURED" and not (
            req.replace_existing and identity["full_name"] in explicit_replacements
        ):
            results.append({"repository": identity["full_name"], "status": "kept"})
        elif metadata["status"] == "INACCESSIBLE":
            results.append({"repository": identity["full_name"], "status": "rejected", "reason": metadata.get("reason", "Secret metadata is inaccessible")})
        else:
            results.append(_configure_repository_secret(identity, normalized_name, secret_value, connection["token"]))
    return {
        "secret_name": normalized_name,
        "configured_count": sum(result["status"] == "configured" for result in results),
        "kept_count": sum(result["status"] == "kept" for result in results),
        "rejected_count": sum(result["status"] == "rejected" for result in results),
        "results": results,
    }


@app.get("/api/repositories/{owner}/{repo}/secrets/{secret_name}/status")
def get_repository_secret_status(owner: str, repo: str, secret_name: str):
    """Return Actions secret metadata state only; GitHub never returns the value."""
    try:
        identity = normalize_github_repository(owner=owner, name=repo)
        normalized_name = _normalize_github_secret_name(secret_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    connection = get_github_connection(DATABASE_URL)
    if not connection:
        raise HTTPException(status_code=401, detail="GitHub not connected")
    metadata = _repository_secret_metadata(identity, normalized_name, connection["token"])
    status_map = {"CONFIGURED": "configured", "MISSING": "not_configured", "INACCESSIBLE": "inaccessible"}
    return {"repository": identity["full_name"], "secret_name": normalized_name, "status": status_map[metadata["status"]]}


@app.get("/api/repositories/secrets/{secret_name}/statuses")
def get_onboarded_repository_secret_statuses(secret_name: str):
    """Return safe metadata states for one secret across system-known onboarded repositories."""
    try:
        normalized_name = _normalize_github_secret_name(secret_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    connection = get_github_connection(DATABASE_URL)
    if not connection:
        raise HTTPException(status_code=401, detail="GitHub not connected")
    targets = _onboarded_secret_repositories()
    return {
        "secret_name": normalized_name,
        "results": [_safe_secret_metadata_result(identity, normalized_name, connection["token"]) for identity in targets],
    }


@app.get("/api/configuration/analysis-services")
def api_analysis_services_configuration():
    """Expose configuration metadata without reading or returning credentials."""
    return {
        "codex": {
            "status": "MANAGED_EXTERNALLY",
            "configuration_source": "GITHUB_ACTIONS_SECRETS",
            "scope": "PER_REPOSITORY",
            "credential_input_enabled": False,
            "credential_update_supported": False,
            "global_configuration_available": False,
        }
    }



from src.core.onboarding import (
    check_onboarding_status, onboard_repository, compute_diff, EXPECTED_WORKFLOW,
    WORKFLOW_PATH, required_analysis_secrets
)
from src.storage.postgres import save_repo_onboarding, get_repo_onboarding


def _onboard_repository_with_secret_check(connection: Dict[str, Any], owner: str, repo: str) -> Dict[str, Any]:
    """Perform workflow onboarding and non-mutating required-secret checks."""
    full_name = f"{owner}/{repo}"
    workflow_status, workflow_details = check_onboarding_status(connection["token"], owner, repo)
    secret_states: List[Dict[str, str]] = []
    if workflow_status != "ERROR":
        identity = normalize_github_repository(owner=owner, name=repo)
        secret_states = _required_repository_secret_statuses(
            identity, connection["token"], required_analysis_secrets()
        )
    result = onboard_repository(
        connection["token"], owner, repo, preflight=(workflow_status, workflow_details)
    )
    result["repository"] = result.get("repository", full_name)
    result["workflow"] = {"status": result.get("status")}
    result["secrets"] = secret_states
    result["overall_status"] = _onboarding_overall_status(result.get("status", "ERROR"), secret_states)
    return result

@app.get("/api/github/repos/{owner}/{repo}/onboarding-status")
def api_onboarding_status(owner: str, repo: str):
    full_name = f"{owner}/{repo}"
    conn = get_github_connection(DATABASE_URL)
    if not conn:
        raise HTTPException(status_code=401, detail="GitHub not connected")
        
    status, details = check_onboarding_status(conn["token"], owner, repo)
    
    # Save to database
    save_repo_onboarding(
        DATABASE_URL, 
        full_name=full_name, 
        status=status, 
        branch_name=details.get("branch"), 
        pr_number=details.get("pr_number"), 
        pr_url=details.get("pr_url")
    )
    
    return {
        "repository": full_name,
        "status": status,
        **details
    }

@app.post("/api/github/repos/{owner}/{repo}/onboard")
def api_onboard_repo(owner: str, repo: str):
    full_name = f"{owner}/{repo}"
    conn = get_github_connection(DATABASE_URL)
    if not conn:
        raise HTTPException(status_code=401, detail="GitHub not connected")

    result = _onboard_repository_with_secret_check(conn, owner, repo)
    
    if result.get("status") == "ERROR":
        detail = result.get("detail", "Onboarding failed")
        if isinstance(detail, dict):
            detail = {**detail, "workflow": result["workflow"], "secrets": result["secrets"], "overall_status": result["overall_status"]}
        raise HTTPException(status_code=500, detail=detail)
        
    save_repo_onboarding(
        DATABASE_URL,
        full_name=full_name,
        status=result["status"],
        branch_name=result.get("branch"),
        pr_number=result.get("pr_number"),
        pr_url=result.get("pr_url")
    )
    
    return result


@app.post("/api/github/repos/onboard/bulk")
def api_onboard_repositories_bulk(req: BulkOnboardRequest):
    """Onboard each requested repository independently; one failure never aborts peers."""
    conn = get_github_connection(DATABASE_URL)
    if not conn:
        raise HTTPException(status_code=401, detail="GitHub not connected")
    results = []
    for target in req.repositories:
        try:
            identity = normalize_github_repository(owner=target.owner, name=target.name)
            result = _onboard_repository_with_secret_check(conn, identity["owner"], identity["name"])
            if result.get("status") != "ERROR":
                save_repo_onboarding(
                    DATABASE_URL,
                    full_name=identity["full_name"],
                    status=result["status"],
                    branch_name=result.get("branch"),
                    pr_number=result.get("pr_number"),
                    pr_url=result.get("pr_url"),
                )
            results.append(result)
        except Exception:
            results.append({
                "repository": f"{target.owner}/{target.name}",
                "status": "ERROR",
                "workflow": {"status": "ERROR"},
                "secrets": [],
                "overall_status": "WORKFLOW_FAILED",
                "detail": "Repository onboarding could not be completed",
            })
    return {"results": results}

@app.get("/api/github/repos/{owner}/{repo}/onboarding-diff")
def api_onboarding_diff(owner: str, repo: str):
    full_name = f"{owner}/{repo}"
    conn = get_github_connection(DATABASE_URL)
    if not conn:
        raise HTTPException(status_code=401, detail="GitHub not connected")
        
    status, details = check_onboarding_status(conn["token"], owner, repo)
    current_content = details.get("current_content", "")
    diff_text = compute_diff(current_content)
    
    return {
        "repository": full_name,
        "status": status,
        "expected_workflow": EXPECTED_WORKFLOW,
        "current_workflow": current_content,
        "diff": diff_text
    }

@app.get("/api/github/repos/{owner}/{repo}/onboarding-pr")
def api_onboarding_pr(owner: str, repo: str):
    full_name = f"{owner}/{repo}"
    conn = get_github_connection(DATABASE_URL)
    if not conn:
        raise HTTPException(status_code=401, detail="GitHub not connected")
        
    status, details = check_onboarding_status(conn["token"], owner, repo)
    if status != "ONBOARDING_PR_OPEN":
        return {"repository": full_name, "has_open_pr": False}
        
    return {
        "repository": full_name,
        "has_open_pr": True,
        "pr_number": details.get("pr_number"),
        "pr_title": details.get("pr_title"),
        "pr_url": details.get("pr_url"),
        "pr_state": details.get("pr_state"),
        "branch": details.get("branch")
    }



from src.storage.postgres import (
    reserve_running_analysis, complete_analysis_run, complete_analysis_run_report,
    fail_analysis_run, get_current_run
)

ANALYSIS_SECRET = os.environ.get("ANALYSIS_SECRET", "dev_secret_key_1234")

class RunStartRequest(BaseModel):
    repository: str
    branch: Optional[str] = None
    commit_sha: Optional[str] = None
    workflow_run_id: Optional[str] = None
    workflow_url: Optional[str] = None

class RunCompleteRequest(BaseModel):
    report: Dict[str, Any]
    workflow_run_id: Optional[str] = None
    commit_sha: Optional[str] = None
    branch: Optional[str] = None

class RunReportRequest(BaseModel):
    repository: Optional[str] = None
    branch: Optional[str] = None
    commit_sha: Optional[str] = None
    workflow_run_id: Optional[str] = None
    workflow_url: Optional[str] = None
    status: Optional[str] = "COMPLETED"
    report: Dict[str, Any]

class RunFailedRequest(BaseModel):
    error_message: str

def _verify_analysis_secret(secret_header: Optional[str]):
    if secret_header != ANALYSIS_SECRET and os.environ.get("ENV") == "production":
        raise HTTPException(status_code=403, detail="Invalid analysis authorization secret")

def _verify_required_analysis_secret(
    authorization: Optional[str] = None,
    x_analysis_secret: Optional[str] = None,
    secret: Optional[str] = None,
):
    supplied = None
    if authorization:
        scheme, _, credential = authorization.partition(" ")
        if scheme.lower() == "bearer" and credential:
            supplied = credential.strip()
    if not supplied and x_analysis_secret:
        supplied = x_analysis_secret.strip()
    if not supplied and secret:
        supplied = secret.strip()

    if not supplied or not hmac.compare_digest(str(supplied), str(ANALYSIS_SECRET)):
        raise HTTPException(status_code=403, detail="Invalid analysis authorization secret")


@app.post("/api/findings/{finding_id}/recheck-result")
def api_finding_recheck_result(
    finding_id: str,
    req: RecheckResultRequest,
    authorization: Optional[str] = Header(None),
    x_analysis_secret: Optional[str] = Header(None),
    secret: Optional[str] = None,
):
    """Accept an authenticated, small result from the GitHub-hosted recheck."""
    _verify_required_analysis_secret(authorization, x_analysis_secret, secret)
    try:
        identity = normalize_github_repository(req.repository)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    tool = str(req.tool or "").strip().lower()
    status = str(req.status or "").strip().upper()
    if tool not in SUPPORTED_RECHECK_TOOLS:
        raise HTTPException(status_code=400, detail="Unsupported recheck tool")
    if status not in {"FIXED", "STILL_PRESENT", "FAILED"}:
        raise HTTPException(status_code=400, detail="Invalid targeted recheck result status")
    try:
        attempt_id = str(uuid.UUID(str(req.attempt_id or "")))
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail="Recheck callback requires a valid attempt ID")
    commit_sha = str(req.commit_sha or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{7,64}", commit_sha):
        raise HTTPException(status_code=400, detail="Recheck callback requires a valid checked commit SHA")
    workflow_run_id = str(req.workflow_run_id or "").strip()
    if not workflow_run_id.isdigit():
        raise HTTPException(status_code=400, detail="Recheck callback requires a valid GitHub workflow run ID")

    finding = _finding_for_recheck(identity["full_name"], finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding was not found in a completed report for this repository")
    if not _finding_supports_recheck_tool(finding, tool):
        raise HTTPException(status_code=400, detail="Recheck tool does not match the selected finding")
    if str(finding.get("rule_id") or "") != str(req.rule_id or ""):
        raise HTTPException(status_code=400, detail="Recheck rule ID does not match the selected finding")

    target_status = status if status in {"FIXED", "STILL_PRESENT"} else "OPEN"
    lifecycle = get_finding_lifecycle(finding_id, DATABASE_URL)
    if lifecycle.get("recheck_attempt_id") != attempt_id:
        raise HTTPException(status_code=409, detail="Stale or unknown targeted recheck callback was ignored")
    if lifecycle.get("last_verified_commit") != commit_sha:
        raise HTTPException(status_code=409, detail="Targeted recheck callback commit does not match the active attempt")
    if lifecycle.get("status") == target_status and lifecycle.get("verification_tool") == tool:
        return {"finding_id": finding_id, "status": target_status, "idempotent": True}
    if lifecycle.get("status") != "RECHECKING":
        raise HTTPException(status_code=409, detail="Targeted recheck callback does not belong to an active attempt")

    # Callback-provided messages are deliberately not persisted: they could
    # contain tool output. Store only a safe lifecycle message instead.
    message = (
        "Targeted GitHub Actions recheck completed."
        if status in {"FIXED", "STILL_PRESENT"}
        else "Targeted GitHub Actions recheck failed or was inconclusive; finding remains open."
    )
    update_finding_lifecycle(
        finding_id=finding_id,
        database_url=DATABASE_URL,
        status=target_status,
        tool=tool,
        scope="project" if tool == "snyk" else "file",
        message=message,
        commit_sha=commit_sha,
        recheck_attempt_id=attempt_id,
        workflow_run_id=workflow_run_id,
        workflow_run_url=f"https://github.com/{identity['full_name']}/actions/runs/{workflow_run_id}",
    )
    return {
        "finding_id": finding_id,
        "repository": identity["full_name"],
        "status": target_status,
        "recheck_status": status,
        "workflow_run_id": workflow_run_id,
        "workflow_run_url": f"https://github.com/{identity['full_name']}/actions/runs/{workflow_run_id}",
    }

def _github_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Repo-Analysis-Orchestrator",
    }

def _parse_iso_datetime(value: Optional[str]):
    if not value:
        return None
    import datetime
    try:
        parsed = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=datetime.timezone.utc)
        return parsed.astimezone(datetime.timezone.utc)
    except Exception:
        return None

def _safe_sync_running_analysis_from_github(owner: str, repo: str, current_run: Dict[str, Any]) -> Dict[str, Any]:
    try:
        return _sync_running_analysis_from_github(owner, repo, current_run)
    except Exception as exc:
        run_id = current_run.get("id") if current_run else None
        print(f"[analysis-sync] sync failed run_id={run_id} repository={owner}/{repo} error={exc}")
        return current_run

def _download_report_from_artifact(artifact: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
    artifact_id = artifact.get("id")
    archive_url = artifact.get("archive_download_url")
    print(f"[analysis-sync] artifact_retrieved id={artifact_id} name={artifact.get('name')}")
    if not archive_url:
        raise RuntimeError(f"Artifact {artifact_id} does not include archive_download_url")

    archive_resp = requests.get(archive_url, headers=headers, timeout=30)
    if archive_resp.status_code != 200:
        raise RuntimeError(f"Artifact download failed: GitHub HTTP {archive_resp.status_code}")

    with zipfile.ZipFile(io.BytesIO(archive_resp.content)) as archive:
        report_names = [
            name for name in archive.namelist()
            if name.endswith("report.json") and not name.endswith("/")
        ]
        if not report_names:
            raise RuntimeError("Artifact archive does not contain report.json")
        with archive.open(report_names[0]) as report_file:
            report = json.load(report_file)

    if not isinstance(report, dict) or not report:
        raise RuntimeError("Artifact report.json is empty or invalid")
    if "findings" not in report:
        raise RuntimeError("Artifact report.json does not contain a findings array")
    return report

def _select_matching_github_run(workflow_runs: List[Dict[str, Any]], started_at):
    import datetime

    # Allow a small clock/timestamp skew between local Postgres reservation time
    # and GitHub's created_at timestamp. The run is still repository-scoped and
    # duplicate-run protection allows only one local RUNNING analysis per repo.
    earliest = None
    if started_at:
        earliest = started_at - datetime.timedelta(minutes=5)

    for gh_run in workflow_runs:
        created_at = _parse_iso_datetime(gh_run.get("created_at"))
        if earliest and created_at and created_at < earliest:
            continue
        return gh_run
    return None

def _sync_running_analysis_from_github(owner: str, repo: str, current_run: Dict[str, Any]) -> Dict[str, Any]:
    if not current_run or current_run.get("status") != "RUNNING":
        return current_run

    conn = get_github_connection(DATABASE_URL)
    if not conn:
        return current_run

    run_id = current_run.get("id")
    full_name = f"{owner}/{repo}"
    branch = current_run.get("branch")
    started_at = _parse_iso_datetime(current_run.get("started_at"))
    headers = _github_headers(conn["token"])
    workflow_id = WORKFLOW_FILE_NAME

    print(f"[analysis-sync] checking run_id={run_id} repository={full_name} workflow={workflow_id} branch={branch}")

    params = {"event": "workflow_dispatch", "per_page": 20}
    if branch:
        params["branch"] = branch

    runs_resp = requests.get(
        f"https://api.github.com/repos/{full_name}/actions/workflows/{workflow_id}/runs",
        headers=headers,
        params=params,
        timeout=15,
    )
    selected_run = None
    if runs_resp.status_code == 200:
        selected_run = _select_matching_github_run(
            runs_resp.json().get("workflow_runs", []),
            started_at,
        )
    else:
        print(f"[analysis-sync] workflow-specific run lookup failed run_id={run_id} repository={full_name} github_status={runs_resp.status_code}; trying repository run lookup")

    if not selected_run:
        repo_runs_resp = requests.get(
            f"https://api.github.com/repos/{full_name}/actions/runs",
            headers=headers,
            params=params,
            timeout=15,
        )
        if repo_runs_resp.status_code != 200:
            print(f"[analysis-sync] repository run lookup failed run_id={run_id} repository={full_name} github_status={repo_runs_resp.status_code}")
            return current_run
        selected_run = _select_matching_github_run(
            repo_runs_resp.json().get("workflow_runs", []),
            started_at,
        )

    if not selected_run:
        print(f"[analysis-sync] no matching workflow run yet run_id={run_id} repository={full_name}")
        return current_run

    gh_run_id = str(selected_run.get("id"))
    gh_status = selected_run.get("status")
    gh_conclusion = selected_run.get("conclusion")
    print(f"[analysis-sync] matched workflow run_id={run_id} repository={full_name} github_workflow_run_id={gh_run_id} status={gh_status} conclusion={gh_conclusion}")

    if gh_status != "completed":
        return current_run

    if gh_conclusion != "success":
        error_message = f"GitHub workflow run {gh_run_id} completed with conclusion {gh_conclusion or 'unknown'}"
        fail_analysis_run(DATABASE_URL, int(run_id), error_message)
        print(f"[analysis-sync] PostgreSQL update run_id={run_id} status=FAILED github_workflow_run_id={gh_run_id}")
        return get_current_run(DATABASE_URL, full_name) or current_run

    artifacts_resp = requests.get(
        f"https://api.github.com/repos/{full_name}/actions/runs/{gh_run_id}/artifacts",
        headers=headers,
        timeout=15,
    )
    if artifacts_resp.status_code != 200:
        print(f"[analysis-sync] artifact list failed run_id={run_id} repository={full_name} github_workflow_run_id={gh_run_id} github_status={artifacts_resp.status_code}")
        return current_run

    artifacts = artifacts_resp.json().get("artifacts", [])
    report_artifact = next(
        (
            artifact for artifact in artifacts
            if not artifact.get("expired") and "repo-analysis-report" in artifact.get("name", "")
        ),
        None,
    )
    if not report_artifact:
        error_message = f"GitHub workflow run {gh_run_id} succeeded but no repo-analysis-report artifact was found"
        fail_analysis_run(DATABASE_URL, int(run_id), error_message)
        print(f"[analysis-sync] PostgreSQL update run_id={run_id} status=FAILED reason=no_artifact github_workflow_run_id={gh_run_id}")
        return get_current_run(DATABASE_URL, full_name) or current_run

    try:
        report = _download_report_from_artifact(report_artifact, headers)
        complete_analysis_run(
            DATABASE_URL,
            int(run_id),
            report,
            workflow_run_id=gh_run_id,
            commit_sha=selected_run.get("head_sha"),
            branch=selected_run.get("head_branch") or branch,
        )
        print(f"[analysis-sync] PostgreSQL update run_id={run_id} status=COMPLETED repository={full_name} github_workflow_run_id={gh_run_id} findings={len(report.get('findings', []))}")
    except Exception as exc:
        error_message = f"GitHub workflow run {gh_run_id} succeeded but report artifact persistence failed: {exc}"
        fail_analysis_run(DATABASE_URL, int(run_id), error_message)
        print(f"[analysis-sync] PostgreSQL update run_id={run_id} status=FAILED reason=artifact_persist_failed github_workflow_run_id={gh_run_id}")

    return get_current_run(DATABASE_URL, full_name) or current_run

@app.post("/api/analysis/runs/start")
def api_start_analysis_run(req: RunStartRequest, secret: Optional[str] = None):
    _verify_analysis_secret(secret)
    is_new, run_data = reserve_running_analysis(
        DATABASE_URL, 
        repository=req.repository, 
        branch=req.branch, 
        commit_sha=req.commit_sha,
        workflow_url=req.workflow_url
    )
    return {"is_new": is_new, "run": run_data}

@app.post("/api/analysis/runs/{run_id}/complete")
def api_complete_analysis_run(run_id: int, req: RunCompleteRequest, secret: Optional[str] = None):
    _verify_analysis_secret(secret)
    try:
        complete_analysis_run(
            DATABASE_URL,
            run_id=run_id,
            report=req.report,
            workflow_run_id=req.workflow_run_id,
            commit_sha=req.commit_sha,
            branch=req.branch
        )
    except ValueError as exc:
        status_code = 404 if "not found" in str(exc).lower() else 400
        raise HTTPException(status_code=status_code, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to complete analysis run: {exc}")
    return {"success": True, "run_id": run_id, "status": "COMPLETED"}

@app.post("/api/analysis/runs/{run_id}/report")
def api_analysis_report_callback(
    run_id: int,
    req: RunReportRequest,
    authorization: Optional[str] = Header(None),
    x_analysis_secret: Optional[str] = Header(None),
    secret: Optional[str] = None,
):
    _verify_required_analysis_secret(
        authorization=authorization,
        x_analysis_secret=x_analysis_secret,
        secret=secret,
    )
    print(
        f"[analysis-callback] received run_id={run_id} "
        f"repository={req.repository} report_exists={bool(req.report)}"
    )
    if req.status and req.status != "COMPLETED":
        raise HTTPException(status_code=400, detail="Report callback only accepts COMPLETED reports")
    if not isinstance(req.report, dict) or not req.report:
        raise HTTPException(status_code=400, detail="Report callback requires a non-empty report object")
    if "findings" not in req.report:
        raise HTTPException(status_code=400, detail="Report callback requires the generated report.json schema")

    try:
        updated_run = complete_analysis_run_report(
            DATABASE_URL,
            run_id,
            req.report,
            repository=req.repository,
            workflow_run_id=req.workflow_run_id,
            commit_sha=req.commit_sha,
            branch=req.branch,
        )
    except ValueError as exc:
        message = str(exc)
        if "not found" in message.lower():
            raise HTTPException(status_code=404, detail=message)
        if "belongs to repository" in message.lower():
            raise HTTPException(status_code=409, detail=message)
        raise HTTPException(status_code=400, detail=message)
    except Exception as exc:
        print(f"[analysis-callback] failed run_id={run_id} repository={req.repository} error={exc}")
        raise HTTPException(status_code=500, detail=f"Failed to persist analysis report: {exc}")

    print(
        f"[analysis-callback] completed run_id={run_id} "
        f"repository={updated_run.get('repository')} findings={len(req.report.get('findings', []))}"
    )
    return {
        "success": True,
        "run_id": run_id,
        "status": updated_run.get("status", "COMPLETED"),
        "repository": updated_run.get("repository"),
        "completed_at": updated_run.get("completed_at"),
        "total_findings": updated_run.get("total_findings", len(req.report.get("findings", []))),
    }

@app.post("/api/analysis/runs/{run_id}/failed")
def api_fail_analysis_run(run_id: int, req: RunFailedRequest, secret: Optional[str] = None):
    _verify_analysis_secret(secret)
    try:
        fail_analysis_run(DATABASE_URL, run_id=run_id, error_message=req.error_message)
    except ValueError as exc:
        status_code = 404 if "not found" in str(exc).lower() else 400
        raise HTTPException(status_code=status_code, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to mark analysis run failed: {exc}")
    return {"success": True, "run_id": run_id, "status": "FAILED"}

@app.get("/api/runs")
def api_list_all_runs():
    res = list_reports()
    return res

@app.get("/api/runs/{run_id}")
def api_get_run_detail(run_id: str):
    return get_report(run_id)

@app.get("/api/github/repos/{owner}/{repo}/runs")
def api_get_repo_runs(owner: str, repo: str):
    full_name = f"{owner}/{repo}"
    current = get_current_run(DATABASE_URL, full_name)
    if current and current.get("status") == "RUNNING":
        _safe_sync_running_analysis_from_github(owner, repo, current)
    return list_reports(repo=full_name)

@app.get("/api/github/repos/{owner}/{repo}/current-run")
def api_get_current_repo_run(owner: str, repo: str):
    full_name = f"{owner}/{repo}"
    current = get_current_run(DATABASE_URL, full_name)
    if not current:
        return {"repository": full_name, "status": "IDLE", "run": None}
    if current.get("status") == "RUNNING":
        current = _safe_sync_running_analysis_from_github(owner, repo, current)
    return {"repository": full_name, "status": current["status"], "run": current}

@app.post("/api/github/repos/{owner}/{repo}/run-analysis")
def api_trigger_run_analysis(owner: str, repo: str):
    full_name = f"{owner}/{repo}"
    
    # 1. Verify GitHub Connection
    conn = get_github_connection(DATABASE_URL)
    if not conn:
        raise HTTPException(status_code=401, detail="GitHub not connected")
        
    token = conn["token"]
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Repo-Analysis-Orchestrator"
    }
        
    # 2. Verify repository access, onboarding status, and workflow availability.
    ob_status, ob_details = check_onboarding_status(token, owner, repo)
    if ob_status not in ("UP_TO_DATE", "DRIFT"):
        raise HTTPException(status_code=400, detail=f"Repository is not onboarded (Status: {ob_status})")
        
    default_branch = ob_details.get("default_branch", "main")
    workflow_id = WORKFLOW_FILE_NAME
    dispatch_payload = {
        "ref": default_branch,
        "inputs": {
            "run_id": None
        }
    }

    repo_resp = requests.get(f"https://api.github.com/repos/{full_name}", headers=headers, timeout=10)
    if repo_resp.status_code != 200:
        detail = {
            "message": f"Repository '{full_name}' is not accessible with the stored GitHub token.",
            "repository": full_name,
            "ref": default_branch,
            **_github_api_error_context(repo_resp),
        }
        raise HTTPException(status_code=repo_resp.status_code if repo_resp.status_code in (403, 404) else 502, detail=detail)

    repo_data = repo_resp.json()
    repo_permissions = repo_data.get("permissions") or {}
    if repo_data.get("private") and not repo_permissions.get("pull"):
        raise HTTPException(
            status_code=403,
            detail={
                "message": f"Private repository '{full_name}' is not readable with the stored GitHub token.",
                "repository": full_name,
                "ref": default_branch,
                "repository_permissions": repo_permissions,
            },
        )
    if not repo_permissions.get("push"):
        raise HTTPException(
            status_code=403,
            detail={
                "message": "GitHub Actions dispatch forbidden: token lacks repository write access for the selected repository.",
                "repository": full_name,
                "ref": default_branch,
                "repository_permissions": repo_permissions,
            },
        )
    
    # Pre-check workflow file on ref to verify workflow_dispatch exists
    workflow_check_url = f"https://api.github.com/repos/{full_name}/contents/{WORKFLOW_PATH}?ref={default_branch}"
    try:
        wf_resp = requests.get(workflow_check_url, headers=headers, timeout=10)
        if wf_resp.status_code == 200:
            wf_data = wf_resp.json()
            if "content" in wf_data:
                content_decoded = base64.b64decode(wf_data["content"]).decode("utf-8", errors="replace")
                if "workflow_dispatch" not in content_decoded:
                    drift_note = " Repository onboarding status is DRIFT and this drift prevents dispatch because the workflow file on the target ref lacks 'workflow_dispatch'." if ob_status == "DRIFT" else ""
                    raise HTTPException(
                        status_code=400,
                        detail={
                            "message": f"Workflow file '{WORKFLOW_PATH}' on ref '{default_branch}' does not contain 'workflow_dispatch'.{drift_note}",
                            "repository": full_name,
                            "workflow_file": WORKFLOW_PATH,
                            "workflow_id": workflow_id,
                            "ref": default_branch,
                            "onboarding_status": ob_status,
                            "drift_prevents_dispatch": ob_status == "DRIFT",
                        },
                    )
        elif wf_resp.status_code == 404:
            raise HTTPException(
                status_code=400,
                detail={
                    "message": f"Workflow file '{WORKFLOW_PATH}' not found on ref '{default_branch}' for repository '{full_name}'.",
                    "repository": full_name,
                    "workflow_file": WORKFLOW_PATH,
                    "workflow_id": workflow_id,
                    "ref": default_branch,
                    "onboarding_status": ob_status,
                    "drift_prevents_dispatch": ob_status == "DRIFT",
                    **_github_api_error_context(wf_resp),
                },
            )
        elif wf_resp.status_code != 200:
            raise HTTPException(
                status_code=wf_resp.status_code if wf_resp.status_code in (403, 404) else 502,
                detail={
                    "message": f"Could not verify workflow file '{WORKFLOW_PATH}' on ref '{default_branch}'.",
                    "repository": full_name,
                    "workflow_file": WORKFLOW_PATH,
                    "workflow_id": workflow_id,
                    "ref": default_branch,
                    "onboarding_status": ob_status,
                    **_github_api_error_context(wf_resp),
                },
            )
    except HTTPException:
        raise
    except Exception as exc:
        print(f"Pre-check warning for {full_name}: {exc}")
        pass

    workflow_api_url = f"https://api.github.com/repos/{full_name}/actions/workflows/{workflow_id}"
    workflow_resp = requests.get(workflow_api_url, headers=headers, timeout=10)
    if workflow_resp.status_code != 200:
        raise HTTPException(
            status_code=workflow_resp.status_code if workflow_resp.status_code in (403, 404) else 502,
            detail={
                "message": f"GitHub Actions workflow '{workflow_id}' is not accessible for repository '{full_name}'.",
                "repository": full_name,
                "workflow_file": WORKFLOW_PATH,
                "workflow_id": workflow_id,
                "ref": default_branch,
                "onboarding_status": ob_status,
                "drift_prevents_dispatch": False,
                **_github_api_error_context(workflow_resp),
            },
        )

    workflow_data = workflow_resp.json()
    workflow_path = workflow_data.get("path")
    if workflow_path and workflow_path != WORKFLOW_PATH:
        raise HTTPException(
            status_code=400,
            detail={
                "message": f"GitHub resolved workflow '{workflow_id}' to '{workflow_path}', expected '{WORKFLOW_PATH}'.",
                "repository": full_name,
                "workflow_file": WORKFLOW_PATH,
                "workflow_id": workflow_id,
                "ref": default_branch,
                "onboarding_status": ob_status,
                "drift_prevents_dispatch": ob_status == "DRIFT",
            },
        )
    
    # 3. ATOMICALLY RESERVE RUN IN POSTGRES BEFORE TRIGGERING GITHUB ACTIONS
    is_new, run_data = reserve_running_analysis(
        DATABASE_URL, 
        repository=full_name, 
        branch=default_branch,
        workflow_url=f"https://github.com/{full_name}/actions"
    )
    
    if not is_new:
        return {
            "status": "already_running",
            "run_id": str(run_data["id"]),
            "repository": full_name,
            "run": run_data,
            "message": "Analysis is already running for this repository."
        }
        
    run_id = run_data["id"]
    
    # 4. Trigger GitHub Actions via workflow_dispatch
    dispatch_url = f"https://api.github.com/repos/{full_name}/actions/workflows/{workflow_id}/dispatches"
    dispatch_payload["inputs"]["run_id"] = str(run_id)
    
    try:
        dispatch_resp = requests.post(
            dispatch_url,
            headers=headers,
            json=dispatch_payload,
            timeout=10
        )
    except Exception as exc:
        err_msg = f"Network error contacting GitHub API: {str(exc)}"
        fail_analysis_run(DATABASE_URL, run_id, err_msg)
        raise HTTPException(status_code=502, detail=err_msg)
    
    # HTTP 204 No Content indicates successful dispatch
    if dispatch_resp.status_code not in (204, 201, 200):
        # Extract GitHub response headers and body without exposing tokens
        resp_body = _safe_response_body(dispatch_resp)
        gh_message = resp_body.get("message", "No message provided by GitHub")
        accepted_perms = dispatch_resp.headers.get("X-Accepted-GitHub-Permissions", "")
        oauth_scopes = dispatch_resp.headers.get("X-OAuth-Scopes", "")
        accepted_scopes = dispatch_resp.headers.get("X-Accepted-OAuth-Scopes", "")
        
        req_perms = accepted_perms or accepted_scopes or oauth_scopes or "actions:write / workflow"
        diagnostic_detail = {
            "repository": full_name,
            "workflow_file": WORKFLOW_PATH,
            "workflow_id": workflow_id,
            "dispatch_url": dispatch_url,
            "ref": default_branch,
            "onboarding_status": ob_status,
            "drift_prevents_dispatch": False,
            "required_permissions": req_perms,
            "repository_permissions": repo_permissions,
            **_github_api_error_context(dispatch_resp),
        }
        
        if dispatch_resp.status_code == 403:
            detail_msg = (
                f"GitHub Actions dispatch forbidden: token lacks Actions write permission or repository/workflow access. "
                f"(GitHub HTTP 403: {gh_message}. Required permissions: {req_perms}. "
                f"Repository permission check: push={repo_permissions.get('push')}, pull={repo_permissions.get('pull')})."
            )
            fail_analysis_run(DATABASE_URL, run_id, detail_msg)
            diagnostic_detail["message"] = detail_msg
            raise HTTPException(status_code=403, detail=diagnostic_detail)
        elif dispatch_resp.status_code == 404:
            detail_msg = (
                f"GitHub Actions workflow not found: '{WORKFLOW_PATH}' on ref '{default_branch}' was not found or is inaccessible. (GitHub HTTP 404: {gh_message})."
            )
            fail_analysis_run(DATABASE_URL, run_id, detail_msg)
            diagnostic_detail["message"] = detail_msg
            raise HTTPException(status_code=404, detail=diagnostic_detail)
        elif dispatch_resp.status_code == 422:
            detail_msg = (
                f"GitHub Actions dispatch unprocessable: workflow file on '{default_branch}' may be missing 'workflow_dispatch' trigger or has syntax errors. (GitHub HTTP 422: {gh_message})."
            )
            fail_analysis_run(DATABASE_URL, run_id, detail_msg)
            diagnostic_detail["message"] = detail_msg
            raise HTTPException(status_code=422, detail=diagnostic_detail)
        else:
            detail_msg = f"Failed to trigger GitHub Actions workflow: HTTP {dispatch_resp.status_code} - {gh_message}"
            fail_analysis_run(DATABASE_URL, run_id, detail_msg)
            diagnostic_detail["message"] = detail_msg
            raise HTTPException(status_code=502, detail=diagnostic_detail)
        
    return {
        "status": "started",
        "run_id": str(run_id),
        "repository": full_name,
        "branch": default_branch,
        "workflow_file": WORKFLOW_PATH,
        "workflow_id": workflow_id,
        "workflow_url": f"https://github.com/{full_name}/actions"
    }

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
