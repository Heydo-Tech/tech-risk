"""PostgreSQL persistence for completed repository analysis reports.

The report is intentionally stored as JSONB first. This preserves the complete
report schema while the UI and query requirements are still being discovered.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS analysis_runs (
    id BIGSERIAL PRIMARY KEY,
    repository TEXT NOT NULL,
    commit_sha TEXT,
    branch TEXT,
    workflow_run_id TEXT,
    status TEXT NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    report JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS finding_lifecycle (
    finding_id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'OPEN',
    first_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_verified_commit TEXT,
    verification_tool TEXT,
    verification_scope TEXT,
    history JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS analysis_runs_repository_idx
    ON analysis_runs (repository);
CREATE INDEX IF NOT EXISTS analysis_runs_completed_at_idx
    ON analysis_runs (completed_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS unique_active_running_analysis
    ON analysis_runs (repository)
    WHERE (status = 'RUNNING');

CREATE INDEX IF NOT EXISTS analysis_runs_report_idx
    ON analysis_runs USING GIN (report);
"""


def _connect(database_url: str):
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - exercised in CLI environments
        raise RuntimeError(
            "PostgreSQL persistence requires psycopg. Install requirements.txt first."
        ) from exc
    # Keep database outages from holding a CI analysis indefinitely. The report
    # is written locally before persistence is attempted and remains available
    # for artifact upload when this connection times out.
    return psycopg.connect(database_url, connect_timeout=10)


def initialize_schema(database_url: str) -> None:
    """Create the persistence table and indexes if they do not exist."""
    with _connect(database_url) as connection:
        with connection.cursor() as cursor:
            cursor.execute(SCHEMA)
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS github_connections (
                id SERIAL PRIMARY KEY,
                github_username TEXT NOT NULL,
                token_credential TEXT NOT NULL,
                token_hint TEXT NOT NULL,
                avatar_url TEXT,
                connected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            ''')
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS managed_repositories (
                github_full_name TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                name TEXT NOT NULL,
                selected BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            ''')
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS repo_onboarding (
                github_full_name TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                branch_name TEXT,
                pr_number INT,
                pr_url TEXT,
                last_checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            ''')
            cursor.execute('''
            ALTER TABLE analysis_runs ALTER COLUMN report DROP NOT NULL;
            ALTER TABLE analysis_runs ALTER COLUMN report SET DEFAULT '{}'::jsonb;
            ''')
            cursor.execute('''
            ALTER TABLE analysis_runs ADD COLUMN IF NOT EXISTS error_message TEXT;
            ALTER TABLE analysis_runs ADD COLUMN IF NOT EXISTS workflow_url TEXT;
            ALTER TABLE analysis_runs ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();
            ''')




def persist_report(
    report: dict[str, Any],
    database_url: str,
    *,
    repository: Optional[str] = None,
    commit_sha: Optional[str] = None,
    branch: Optional[str] = None,
    workflow_run_id: Optional[str] = None,
    status: str = "COMPLETED",
) -> int:
    """Persist a report and return its database id.

    ``repository`` defaults to the report's ``repo`` field. The report remains
    immutable: every workflow run is represented by a separate row.
    """
    repository_name = repository or report.get("repo")
    if not repository_name:
        raise ValueError("A repository name is required to persist a report")

    initialize_schema(database_url)
    with _connect(database_url) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO analysis_runs
                    (repository, commit_sha, branch, workflow_run_id, status, report)
                VALUES (%s, %s, %s, %s, %s, %s::jsonb)
                RETURNING id
                """,
                (
                    repository_name,
                    commit_sha,
                    branch,
                    workflow_run_id,
                    status,
                    json.dumps(report),
                ),
            )
            row = cursor.fetchone()
            if row is None:  # pragma: no cover - defensive database guard
                raise RuntimeError("PostgreSQL did not return the inserted run id")
            return int(row[0])


def persist_report_file(
    report_path: str | os.PathLike[str],
    database_url: str,
    **metadata: Optional[str],
) -> int:
    """Load a JSON report file and persist it."""
    path = Path(report_path)
    with path.open("r", encoding="utf-8") as report_file:
        report = json.load(report_file)
    if not isinstance(report, dict):
        raise ValueError("The report file must contain a JSON object")
    return persist_report(report, database_url, **metadata)
def update_finding_lifecycle(
    finding_id: str,
    database_url: str,
    status: str,
    commit_sha: Optional[str] = None,
    tool: Optional[str] = None,
    scope: Optional[str] = None,
    message: Optional[str] = None
) -> None:
    initialize_schema(database_url)
    with _connect(database_url) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT history FROM finding_lifecycle WHERE finding_id = %s", (finding_id,))
            row = cursor.fetchone()
            
            import datetime
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            
            history_entry = {
                "timestamp": now_iso,
                "status": status,
                "commit": commit_sha,
                "tool": tool,
                "message": message
            }
            
            if row is None:
                new_history = [history_entry]
                cursor.execute(
                    """
                    INSERT INTO finding_lifecycle
                        (finding_id, status, last_verified_commit, verification_tool, verification_scope, history)
                    VALUES (%s, %s, %s, %s, %s, %s::jsonb)
                    """,
                    (finding_id, status, commit_sha, tool, scope, json.dumps(new_history))
                )
            else:
                history = row[0]
                history.append(history_entry)
                cursor.execute(
                    """
                    UPDATE finding_lifecycle
                    SET status = %s,
                        last_checked_at = NOW(),
                        last_verified_commit = %s,
                        verification_tool = %s,
                        verification_scope = %s,
                        history = %s::jsonb
                    WHERE finding_id = %s
                    """,
                    (status, commit_sha, tool, scope, json.dumps(history), finding_id)
                )

def get_finding_lifecycle(finding_id: str, database_url: str) -> dict[str, Any]:
    initialize_schema(database_url)
    with _connect(database_url) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT status, first_detected_at, last_checked_at, last_verified_commit, verification_tool, verification_scope, history FROM finding_lifecycle WHERE finding_id = %s", (finding_id,))
            row = cursor.fetchone()
            if row:
                return {
                    "status": row[0],
                    "first_detected_at": row[1].isoformat() if row[1] else None,
                    "last_checked_at": row[2].isoformat() if row[2] else None,
                    "last_verified_commit": row[3],
                    "verification_tool": row[4],
                    "verification_scope": row[5],
                    "history": row[6]
                }
            return {}


# In-memory fallback cache when Postgres is offline
_in_memory_github_conn = None
_in_memory_managed_repos = {}

def get_github_connection(database_url: str):
    global _in_memory_github_conn
    try:
        initialize_schema(database_url)
        with _connect(database_url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, github_username, token_credential, token_hint, avatar_url, connected_at FROM github_connections ORDER BY id DESC LIMIT 1")
                row = cur.fetchone()
                if row:
                    return {
                        "id": row[0],
                        "username": row[1],
                        "token": row[2],
                        "token_hint": row[3],
                        "avatar_url": row[4],
                        "connected_at": row[5].isoformat() if row[5] else None
                    }
                return None
    except Exception as e:
        print("DB connection failed for get_github_connection, using fallback:", e)
        return _in_memory_github_conn

def save_github_connection(database_url: str, username: str, token: str, hint: str, avatar_url: str):
    global _in_memory_github_conn
    import datetime
    _in_memory_github_conn = {
        "id": 1,
        "username": username,
        "token": token,
        "token_hint": hint,
        "avatar_url": avatar_url,
        "connected_at": datetime.datetime.now().isoformat()
    }
    try:
        initialize_schema(database_url)
        with _connect(database_url) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM github_connections")
                cur.execute(
                    "INSERT INTO github_connections (github_username, token_credential, token_hint, avatar_url) VALUES (%s, %s, %s, %s)",
                    (username, token, hint, avatar_url)
                )
    except Exception as e:
        print("DB connection failed for save_github_connection, saved to fallback memory:", e)

def delete_github_connection(database_url: str):
    global _in_memory_github_conn
    _in_memory_github_conn = None
    try:
        initialize_schema(database_url)
        with _connect(database_url) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM github_connections")
    except Exception as e:
        print("DB connection failed for delete_github_connection:", e)

def get_managed_repos(database_url: str):
    global _in_memory_managed_repos
    try:
        initialize_schema(database_url)
        with _connect(database_url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT github_full_name, owner, name, selected FROM managed_repositories")
                rows = cur.fetchall()
                return [{"full_name": r[0], "owner": r[1], "name": r[2], "selected": r[3]} for r in rows]
    except Exception as e:
        print("DB connection failed for get_managed_repos, using fallback:", e)
        return list(_in_memory_managed_repos.values())

def set_managed_repo(database_url: str, full_name: str, owner: str, name: str, selected: bool):
    global _in_memory_managed_repos
    _in_memory_managed_repos[full_name] = {"full_name": full_name, "owner": owner, "name": name, "selected": selected}
    try:
        initialize_schema(database_url)
        with _connect(database_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO managed_repositories (github_full_name, owner, name, selected) 
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (github_full_name) DO UPDATE SET selected = EXCLUDED.selected
                    """,
                    (full_name, owner, name, selected)
                )
    except Exception as e:
        print("DB connection failed for set_managed_repo, saved to fallback memory:", e)


_in_memory_repo_onboarding = {}

def get_repo_onboarding(database_url: str, full_name: str):
    global _in_memory_repo_onboarding
    try:
        initialize_schema(database_url)
        with _connect(database_url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT github_full_name, status, branch_name, pr_number, pr_url, last_checked_at FROM repo_onboarding WHERE github_full_name = %s", (full_name,))
                row = cur.fetchone()
                if row:
                    return {
                        "github_full_name": row[0],
                        "status": row[1],
                        "branch_name": row[2],
                        "pr_number": row[3],
                        "pr_url": row[4],
                        "last_checked_at": row[5].isoformat() if row[5] else None
                    }
                return None
    except Exception as e:
        print("DB connection failed for get_repo_onboarding, using fallback:", e)
        return _in_memory_repo_onboarding.get(full_name)

def save_repo_onboarding(database_url: str, full_name: str, status: str, branch_name: str = None, pr_number: int = None, pr_url: str = None):
    global _in_memory_repo_onboarding
    import datetime
    _in_memory_repo_onboarding[full_name] = {
        "github_full_name": full_name,
        "status": status,
        "branch_name": branch_name,
        "pr_number": pr_number,
        "pr_url": pr_url,
        "last_checked_at": datetime.datetime.now().isoformat()
    }
    try:
        initialize_schema(database_url)
        with _connect(database_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO repo_onboarding (github_full_name, status, branch_name, pr_number, pr_url, last_checked_at)
                    VALUES (%s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (github_full_name) DO UPDATE SET 
                        status = EXCLUDED.status,
                        branch_name = EXCLUDED.branch_name,
                        pr_number = EXCLUDED.pr_number,
                        pr_url = EXCLUDED.pr_url,
                        last_checked_at = NOW()
                    """,
                    (full_name, status, branch_name, pr_number, pr_url)
                )
    except Exception as e:
        print("DB connection failed for save_repo_onboarding, saved to fallback memory:", e)


_in_memory_runs = {}
_run_counter = 100

def reserve_running_analysis(database_url: str, repository: str, branch: str = None, commit_sha: str = None, workflow_url: str = None):
    global _in_memory_runs, _run_counter
    try:
        initialize_schema(database_url)
        with _connect(database_url) as conn:
            with conn.cursor() as cur:
                # Advisory lock transaction scope to serialize simultaneous checks for the same repository
                cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (repository,))
                
                # Check for existing RUNNING analysis
                cur.execute(
                    "SELECT id, repository, branch, commit_sha, status, started_at, workflow_url FROM analysis_runs WHERE repository = %s AND status = 'RUNNING'",
                    (repository,)
                )
                existing = cur.fetchone()
                if existing:
                    return False, {
                        "id": str(existing[0]),
                        "repository": existing[1],
                        "branch": existing[2],
                        "commit_sha": existing[3],
                        "status": existing[4],
                        "started_at": existing[5].isoformat() if existing[5] else None,
                        "workflow_url": existing[6]
                    }

                # Insert RUNNING analysis row
                try:
                    cur.execute(
                        """
                        INSERT INTO analysis_runs (repository, branch, commit_sha, status, started_at, report, workflow_url, updated_at)
                        VALUES (%s, %s, %s, 'RUNNING', NOW(), '{}'::jsonb, %s, NOW())
                        RETURNING id, started_at
                        """,
                        (repository, branch, commit_sha, workflow_url)
                    )
                    new_row = cur.fetchone()
                    conn.commit()
                    return True, {
                        "id": str(new_row[0]),
                        "repository": repository,
                        "branch": branch,
                        "commit_sha": commit_sha,
                        "status": "RUNNING",
                        "started_at": new_row[1].isoformat() if new_row[1] else None,
                        "workflow_url": workflow_url
                    }
                except Exception as insert_err:
                    conn.rollback()
                    # Re-query active run if unique violation or race occurred
                    cur.execute(
                        "SELECT id, repository, branch, commit_sha, status, started_at, workflow_url FROM analysis_runs WHERE repository = %s AND status = 'RUNNING'",
                        (repository,)
                    )
                    active = cur.fetchone()
                    if active:
                        return False, {
                            "id": str(active[0]),
                            "repository": active[1],
                            "branch": active[2],
                            "commit_sha": active[3],
                            "status": active[4],
                            "started_at": active[5].isoformat() if active[5] else None,
                            "workflow_url": active[6]
                        }
                    raise insert_err
    except Exception as e:
        print("DB connection failed for reserve_running_analysis, checking memory fallback:", e)
        # Memory fallback (thread-safe lock for local fallback mode)
        for r_id, r in list(_in_memory_runs.items()):
            if r.get("repository") == repository and r.get("status") == "RUNNING":
                return False, r
        _run_counter += 1
        import datetime
        new_run = {
            "id": str(_run_counter),
            "repository": repository,
            "branch": branch,
            "commit_sha": commit_sha,
            "status": "RUNNING",
            "started_at": datetime.datetime.now().isoformat(),
            "workflow_url": workflow_url
        }
        _in_memory_runs[_run_counter] = new_run
        return True, new_run


def complete_analysis_run(database_url: str, run_id: int, report: dict, workflow_run_id: str = None, commit_sha: str = None, branch: str = None):
    if not isinstance(report, dict) or not report:
        raise ValueError("Cannot complete analysis run without a non-empty report")

    global _in_memory_runs
    if run_id in _in_memory_runs:
        _in_memory_runs[run_id]["status"] = "COMPLETED"
        _in_memory_runs[run_id]["report"] = report
        _in_memory_runs[run_id]["total_findings"] = len(report.get("findings", []))
    try:
        initialize_schema(database_url)
        with _connect(database_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE analysis_runs
                    SET status = 'COMPLETED',
                        completed_at = NOW(),
                        updated_at = NOW(),
                        report = %s::jsonb,
                        workflow_run_id = COALESCE(%s, workflow_run_id),
                        commit_sha = COALESCE(%s, commit_sha),
                        branch = COALESCE(%s, branch)
                    WHERE id = %s
                    """,
                    (json.dumps(report), workflow_run_id, commit_sha, branch, run_id)
                )
                if cur.rowcount == 0:
                    raise ValueError(f"Analysis run {run_id} was not found")
                conn.commit()
    except Exception as e:
        print("DB connection failed for complete_analysis_run:", e)
        raise

def get_analysis_run_by_id(database_url: str, run_id: int):
    global _in_memory_runs
    if run_id in _in_memory_runs:
        return dict(_in_memory_runs[run_id])
    try:
        initialize_schema(database_url)
        with _connect(database_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, repository, branch, commit_sha, workflow_run_id, status,
                           started_at, completed_at, error_message, workflow_url, report
                    FROM analysis_runs
                    WHERE id = %s
                    """,
                    (run_id,)
                )
                row = cur.fetchone()
                if not row:
                    return None
                report = row[10] if isinstance(row[10], dict) else {}
                return {
                    "id": row[0],
                    "repository": row[1],
                    "branch": row[2],
                    "commit_sha": row[3],
                    "workflow_run_id": row[4],
                    "status": row[5],
                    "started_at": row[6].isoformat() if row[6] else None,
                    "completed_at": row[7].isoformat() if row[7] else None,
                    "error_message": row[8],
                    "workflow_url": row[9],
                    "report": report,
                    "total_findings": len(report.get("findings", [])) if isinstance(report, dict) else 0,
                }
    except Exception as e:
        print("DB connection failed for get_analysis_run_by_id:", e)
        raise

def complete_analysis_run_report(
    database_url: str,
    run_id: int,
    report: dict,
    *,
    repository: str = None,
    workflow_run_id: str = None,
    commit_sha: str = None,
    branch: str = None,
):
    if not isinstance(report, dict) or not report:
        raise ValueError("Cannot complete analysis run without a non-empty report")

    existing = get_analysis_run_by_id(database_url, run_id)
    if not existing:
        raise ValueError(f"Analysis run {run_id} was not found")

    if repository and existing.get("repository") != repository:
        raise ValueError(
            f"Analysis run {run_id} belongs to repository '{existing.get('repository')}', not '{repository}'"
        )

    status = existing.get("status")
    if status == "FAILED":
        raise ValueError(f"Analysis run {run_id} is FAILED and cannot be completed by report callback")
    if status not in ("RUNNING", "COMPLETED"):
        raise ValueError(f"Analysis run {run_id} is in unsupported status '{status}'")
    if status == "COMPLETED" and isinstance(existing.get("report"), dict) and existing.get("report"):
        return existing

    complete_analysis_run(
        database_url,
        run_id,
        report,
        workflow_run_id=workflow_run_id,
        commit_sha=commit_sha,
        branch=branch,
    )
    return get_analysis_run_by_id(database_url, run_id)

def fail_analysis_run(database_url: str, run_id: int, error_message: str):
    global _in_memory_runs
    if run_id in _in_memory_runs:
        _in_memory_runs[run_id]["status"] = "FAILED"
        _in_memory_runs[run_id]["error_message"] = error_message
    try:
        initialize_schema(database_url)
        with _connect(database_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE analysis_runs
                    SET status = 'FAILED',
                        completed_at = NOW(),
                        updated_at = NOW(),
                        error_message = %s
                    WHERE id = %s
                    """,
                    (error_message, run_id)
                )
                if cur.rowcount == 0:
                    raise ValueError(f"Analysis run {run_id} was not found")
                conn.commit()
    except Exception as e:
        print("DB connection failed for fail_analysis_run:", e)
        raise

def get_current_run(database_url: str, repository: str):
    global _in_memory_runs
    try:
        initialize_schema(database_url)
        with _connect(database_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, repository, branch, commit_sha, workflow_run_id, status, started_at, completed_at, error_message, workflow_url, report
                    FROM analysis_runs
                    WHERE repository = %s
                    ORDER BY id DESC LIMIT 1
                    """,
                    (repository,)
                )
                row = cur.fetchone()
                if row:
                    findings_count = len(row[10].get("findings", [])) if isinstance(row[10], dict) else 0
                    return {
                        "id": row[0],
                        "repository": row[1],
                        "branch": row[2],
                        "commit_sha": row[3],
                        "workflow_run_id": row[4],
                        "status": row[5],
                        "started_at": row[6].isoformat() if row[6] else None,
                        "completed_at": row[7].isoformat() if row[7] else None,
                        "error_message": row[8],
                        "workflow_url": row[9],
                        "total_findings": findings_count
                    }
                return None
    except Exception as e:
        print("DB connection failed for get_current_run, using fallback:", e)
        matching = [r for r in _in_memory_runs.values() if r["repository"] == repository]
        if matching:
            return sorted(matching, key=lambda x: x["id"], reverse=True)[0]
        return None
