import base64
import json
import difflib
import requests
from typing import Dict, Any, Optional, Tuple

EXPECTED_WORKFLOW = """name: Code Analysis

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
    uses: manasvipaweria/repo-analysis/.github/workflows/reusable-analysis.yml@main
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
    uses: manasvipaweria/repo-analysis/.github/workflows/reusable-finding-recheck.yml@main
    with:
      finding_id: ${{ inputs.recheck_finding_id }}
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
"""

WORKFLOW_PATH = ".github/workflows/code-analysis.yml"
BRANCH_PREFIX = "chore/onboard-repo-analysis"

SAFE_GITHUB_RESPONSE_HEADERS = (
    "X-Accepted-GitHub-Permissions",
    "X-OAuth-Scopes",
    "X-Accepted-OAuth-Scopes",
    "X-GitHub-Request-Id",
)

def _headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Repo-Analysis-Onboarder"
    }

def _normalize(text: str) -> str:
    return "\n".join([line.rstrip() for line in text.strip().splitlines()])

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

def _github_error_detail(
    response: requests.Response,
    *,
    message: str,
    repository: str,
    endpoint: str,
    branch: Optional[str] = None,
    request_url: Optional[str] = None,
    workflow_path: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "message": message,
        "repository": repository,
        "branch": branch,
        "endpoint": endpoint,
        "request_url": request_url,
        "workflow_path": workflow_path,
        "github_status": response.status_code,
        "github_response": _safe_response_body(response),
        "github_headers": _safe_response_headers(response),
    }

def check_onboarding_status(token: str, owner: str, repo: str) -> Tuple[str, Dict[str, Any]]:
    full_name = f"{owner}/{repo}"
    headers = _headers(token)
    
    # 1. Fetch repo details for default branch
    r_resp = requests.get(f"https://api.github.com/repos/{full_name}", headers=headers, timeout=10)
    if r_resp.status_code == 404:
        return "ERROR", {"detail": "Repository not found or inaccessible"}
    if r_resp.status_code != 200:
        return "ERROR", {"detail": f"GitHub API error: {r_resp.status_code}"}
        
    repo_data = r_resp.json()
    default_branch = repo_data.get("default_branch", "main")
    
    # 2. Check if workflow file exists on default branch
    f_resp = requests.get(
        f"https://api.github.com/repos/{full_name}/contents/{WORKFLOW_PATH}?ref={default_branch}", 
        headers=headers, 
        timeout=10
    )
    
    if f_resp.status_code == 200:
        content_json = f_resp.json()
        if "content" in content_json:
            current_content = base64.b64decode(content_json["content"]).decode("utf-8", errors="replace")
            if _normalize(current_content) == _normalize(EXPECTED_WORKFLOW):
                return "UP_TO_DATE", {"default_branch": default_branch, "file_sha": content_json.get("sha")}
            else:
                return "DRIFT", {"default_branch": default_branch, "current_content": current_content, "file_sha": content_json.get("sha")}
                
    # 3. If workflow file does not exist, check for open onboarding PRs
    prs_resp = requests.get(f"https://api.github.com/repos/{full_name}/pulls?state=open", headers=headers, timeout=10)
    if prs_resp.status_code == 200:
        open_prs = prs_resp.json()
        for pr in open_prs:
            ref = pr.get("head", {}).get("ref", "")
            if ref.startswith(BRANCH_PREFIX) or ref.startswith("setup/code-analysis"):
                return "ONBOARDING_PR_OPEN", {
                    "default_branch": default_branch,
                    "pr_number": pr.get("number"),
                    "pr_title": pr.get("title"),
                    "pr_url": pr.get("html_url"),
                    "branch": ref,
                    "pr_state": pr.get("state")
                }
                
    return "NOT_ONBOARDED", {"default_branch": default_branch}

def onboard_repository(token: str, owner: str, repo: str) -> Dict[str, Any]:
    full_name = f"{owner}/{repo}"
    headers = _headers(token)
    
    status, details = check_onboarding_status(token, owner, repo)
    if status in ("UP_TO_DATE", "ERROR"):
        return {"status": status, **details}
    if status == "ONBOARDING_PR_OPEN":
        return {"status": status, **details}
        
    default_branch = details.get("default_branch", "main")
    
    # Get latest commit SHA of default branch
    ref_resp = requests.get(f"https://api.github.com/repos/{full_name}/git/ref/heads/{default_branch}", headers=headers, timeout=10)
    if ref_resp.status_code != 200:
        return {
            "status": "ERROR",
            "detail": _github_error_detail(
                ref_resp,
                message=f"Could not resolve default branch '{default_branch}' head SHA.",
                repository=full_name,
                endpoint="get_default_branch_ref",
                branch=default_branch,
            ),
        }
        
    base_sha = ref_resp.json()["object"]["sha"]
    branch_name = BRANCH_PREFIX
    
    # Create branch
    create_ref_resp = requests.post(
        f"https://api.github.com/repos/{full_name}/git/refs",
        headers=headers,
        json={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
        timeout=10
    )
    
    # 422 usually means branch already exists
    if create_ref_resp.status_code not in (201, 422):
        return {
            "status": "ERROR",
            "detail": _github_error_detail(
                create_ref_resp,
                message=(
                    f"GitHub branch creation forbidden or failed for '{branch_name}'. "
                    "Token may lack Contents write access, repository write access, or org approval."
                ),
                repository=full_name,
                endpoint="create_onboarding_branch",
                branch=branch_name,
            ),
        }
        
    # Put file on branch
    file_data = {
        "message": "chore: add code-analysis workflow",
        "content": base64.b64encode(EXPECTED_WORKFLOW.encode("utf-8")).decode("utf-8"),
        "branch": branch_name
    }
    
    # If file exists on branch, include sha
    b_file_resp = requests.get(
        f"https://api.github.com/repos/{full_name}/contents/{WORKFLOW_PATH}?ref={branch_name}",
        headers=headers,
        timeout=10
    )
    if b_file_resp.status_code == 200:
        file_data["sha"] = b_file_resp.json().get("sha")
        
    put_url = f"https://api.github.com/repos/{full_name}/contents/{WORKFLOW_PATH}"
    put_resp = requests.put(
        put_url,
        headers=headers,
        json=file_data,
        timeout=10
    )
    if put_resp.status_code not in (200, 201):
        return {
            "status": "ERROR",
            "detail": _github_error_detail(
                put_resp,
                message=(
                    f"GitHub rejected the workflow-file commit request for '{WORKFLOW_PATH}' "
                    f"on branch '{branch_name}'. See github_response and github_headers for the exact GitHub reason."
                ),
                repository=full_name,
                endpoint="commit_workflow_file",
                branch=branch_name,
                request_url=put_url,
                workflow_path=WORKFLOW_PATH,
            ),
        }
        
    # Create PR
    pr_data = {
        "title": "chore: setup code-analysis workflow",
        "body": "This pull request sets up the centralized code-analysis workflow.",
        "head": branch_name,
        "base": default_branch
    }
    pr_resp = requests.post(
        f"https://api.github.com/repos/{full_name}/pulls",
        headers=headers,
        json=pr_data,
        timeout=10
    )
    
    if pr_resp.status_code in (201, 200):
        pr = pr_resp.json()
        return {
            "status": "ONBOARDING_PR_OPEN",
            "branch": branch_name,
            "pr_number": pr.get("number"),
            "pr_url": pr.get("html_url"),
            "repository": full_name,
            "base_branch": default_branch
        }
    elif pr_resp.status_code == 422:
        # Check if PR already exists
        prs_resp = requests.get(f"https://api.github.com/repos/{full_name}/pulls?state=open", headers=headers, timeout=10)
        if prs_resp.status_code == 200:
            for pr in prs_resp.json():
                if pr.get("head", {}).get("ref") == branch_name:
                    return {
                        "status": "ONBOARDING_PR_OPEN",
                        "branch": branch_name,
                        "pr_number": pr.get("number"),
                        "pr_url": pr.get("html_url"),
                        "repository": full_name,
                        "base_branch": default_branch
                    }
                    
    return {
        "status": "ERROR",
        "detail": _github_error_detail(
            pr_resp,
            message=(
                f"GitHub rejected creating the onboarding pull request from '{branch_name}' to '{default_branch}'. "
                "Token may lack Pull requests write access or repository write access."
            ),
            repository=full_name,
            endpoint="create_onboarding_pr",
            branch=branch_name,
        ),
    }

def compute_diff(current_content: str) -> str:
    diff_lines = difflib.unified_diff(
        current_content.splitlines(),
        EXPECTED_WORKFLOW.splitlines(),
        fromfile="current/.github/workflows/code-analysis.yml",
        tofile="expected/.github/workflows/code-analysis.yml",
        lineterm=""
    )
    return "\n".join(diff_lines)
