"""Validation and dispatch payload construction for GitHub-hosted rechecks.

The backend deliberately does not clone or execute repository code. GitHub
Actions checks out the selected repository and runs the allowlisted tool.
"""

import re
from pathlib import PurePosixPath
from urllib.parse import urlparse


SUPPORTED_RECHECK_TOOLS = frozenset({"semgrep", "ruff", "bandit", "deslint", "snyk"})
_FILE_TARGETED_TOOLS = frozenset({"semgrep", "ruff", "bandit", "deslint"})
_GITHUB_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def normalize_github_repository(repository: str = None, owner: str = None, name: str = None) -> dict:
    """Normalize full names, owner/name pairs, and GitHub URLs to one identity."""
    repository = (repository or "").strip()
    owner = (owner or "").strip()
    name = (name or "").strip()
    parsed_owner = parsed_name = None

    if repository.startswith(("http://", "https://")):
        parsed = urlparse(repository)
        if parsed.hostname not in {"github.com", "www.github.com"}:
            raise ValueError("Repository URL must point to github.com")
        parts = [part for part in parsed.path.strip("/").split("/") if part]
        if len(parts) != 2:
            raise ValueError("GitHub repository URL must contain an owner and repository name")
        parsed_owner, parsed_name = parts
        if parsed_name.endswith(".git"):
            parsed_name = parsed_name[:-4]
    elif "/" in repository:
        parts = [part for part in repository.split("/") if part]
        if len(parts) != 2:
            raise ValueError("Repository full name must be in owner/name format")
        parsed_owner, parsed_name = parts
    elif repository:
        parsed_name = repository

    canonical_owner = parsed_owner or owner
    canonical_name = parsed_name or name
    if parsed_owner and owner and parsed_owner != owner:
        raise ValueError("Repository owner does not match the supplied full name")
    if parsed_name and name and parsed_name != name:
        raise ValueError("Repository name does not match the supplied full name")
    if not canonical_owner or not canonical_name:
        raise ValueError("Repository must include an owner and repository name")
    if not _GITHUB_SEGMENT.fullmatch(canonical_owner) or not _GITHUB_SEGMENT.fullmatch(canonical_name):
        raise ValueError("Repository owner or name contains invalid characters")

    full_name = f"{canonical_owner}/{canonical_name}"
    return {
        "owner": canonical_owner,
        "name": canonical_name,
        "full_name": full_name,
        "clone_url": f"https://github.com/{full_name}.git",
    }


def validate_recheck_file_path(file_path: str | None) -> str | None:
    """Validate a repository-relative POSIX path without accessing disk."""
    if not file_path:
        return None
    if "\\" in file_path:
        raise ValueError("Recheck file path must use repository-relative POSIX separators")
    path = PurePosixPath(file_path)
    if path.is_absolute() or ".." in path.parts or str(path) in {"", "."}:
        raise ValueError("Recheck file path must stay within the repository")
    return path.as_posix()


def build_recheck_dispatch(finding_id: str, req, attempt_id: str) -> tuple[dict, dict]:
    """Return canonical repository identity and a strict workflow input payload."""
    tool = str(req.tool or "").strip().lower()
    if tool not in SUPPORTED_RECHECK_TOOLS:
        raise ValueError(f"Targeted recheck not supported for tool: {tool or 'missing'}")
    if not req.rule_id:
        raise ValueError("Targeted recheck requires the original rule ID")
    commit_sha = str(getattr(req, "commit_sha", None) or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{7,64}", commit_sha):
        raise ValueError("Targeted recheck requires the full report commit SHA")
    if not attempt_id:
        raise ValueError("Targeted recheck requires a server-generated attempt ID")

    identity = normalize_github_repository(
        getattr(req, "repository", None),
        getattr(req, "owner", None),
        getattr(req, "name", None),
    )
    file_path = validate_recheck_file_path(getattr(req, "file", None))
    if tool in _FILE_TARGETED_TOOLS and not file_path:
        raise ValueError(f"{tool} recheck requires a repository-relative file path")

    return identity, {
        "recheck_finding_id": str(finding_id),
        "recheck_attempt_id": str(attempt_id),
        "recheck_tool": tool,
        "recheck_rule_id": str(req.rule_id),
        "recheck_file_path": file_path or "",
        "recheck_line_start": str(getattr(req, "line", None) or ""),
        "recheck_line_end": str(getattr(req, "line_end", None) or getattr(req, "line", None) or ""),
        "recheck_commit_sha": commit_sha,
    }
