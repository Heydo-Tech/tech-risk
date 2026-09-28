import unittest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
import concurrent.futures
import base64
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.api.server import app
from src.storage.postgres import (
    reserve_running_analysis, complete_analysis_run, fail_analysis_run, get_current_run
)

# Mock state setup for tests
import src.api.server
mock_db = {}

def mock_get_github_connection(url):
    return mock_db.get("conn")

def mock_get_repo_onboarding(url, full_name):
    return {"status": "UP_TO_DATE", "github_full_name": full_name}

def mock_check_onboarding_status(token, owner, repo):
    return "UP_TO_DATE", {"default_branch": "main"}

src.api.server.get_github_connection = mock_get_github_connection
src.api.server.get_repo_onboarding = mock_get_repo_onboarding
src.api.server.check_onboarding_status = mock_check_onboarding_status

import src.core.onboarding
src.core.onboarding.check_onboarding_status = mock_check_onboarding_status

client = TestClient(app)

VALID_WORKFLOW_CONTENT = base64.b64encode(b"""
name: Code Analysis
on:
  workflow_dispatch:
jobs:
  analysis:
    uses: owner/repo/.github/workflows/reusable-analysis.yml@main
""").decode("utf-8")


def mock_preflight_get(url, *args, **kwargs):
    resp = MagicMock()
    resp.status_code = 200
    resp.headers = {}
    if "/contents/.github/workflows/code-analysis.yml" in url:
        resp.json.return_value = {"content": VALID_WORKFLOW_CONTENT}
    elif "/actions/workflows/code-analysis.yml" in url:
        resp.json.return_value = {
            "id": 12345,
            "path": ".github/workflows/code-analysis.yml",
            "state": "active",
        }
    else:
        resp.json.return_value = {
            "private": False,
            "permissions": {"pull": True, "push": True},
        }
    return resp

class TestPostgresConcurrency(unittest.TestCase):
    
    def setUp(self):
        mock_db.clear()
        mock_db["conn"] = {"username": "testuser", "token": "ghp_valid_token_123"}
        
    @patch('src.api.server.requests.get', side_effect=mock_preflight_get)
    @patch('src.api.server.reserve_running_analysis')
    @patch('src.api.server.requests.post')
    def test_1_no_existing_run_creates_new_run(self, mock_post, mock_reserve, mock_get):
        mock_reserve.return_value = (True, {"id": "1001", "status": "RUNNING", "repository": "owner/repo"})
        mock_post.return_value = MagicMock(status_code=204) # GitHub dispatch success
        
        res = client.post("/api/github/repos/owner/repo/run-analysis")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "started")
        self.assertEqual(data["run_id"], "1001")

    @patch('src.api.server.requests.get', side_effect=mock_preflight_get)
    @patch('src.api.server.reserve_running_analysis')
    def test_2_existing_running_returns_already_running(self, mock_reserve, mock_get):
        mock_reserve.return_value = (False, {"id": "1001", "status": "RUNNING", "repository": "owner/repo"})
        
        res = client.post("/api/github/repos/owner/repo/run-analysis")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "already_running")
        self.assertEqual(data["run_id"], "1001")
        self.assertIn("already running", data["message"])

    def test_3_simultaneous_concurrent_requests(self):
        # Test real thread concurrency on endpoint using in-memory or database locks
        with patch('src.api.server.requests.get', side_effect=mock_preflight_get), patch('src.api.server.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=204)
            
            def trigger_request():
                return client.post("/api/github/repos/owner/concurrent-repo/run-analysis")

            # Fire 2 requests simultaneously using ThreadPoolExecutor
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(trigger_request), executor.submit(trigger_request)]
                results = [f.result().json() for f in concurrent.futures.as_completed(futures)]

            statuses = [r["status"] for r in results]
            run_ids = [r["run_id"] for r in results]

            # Exactly ONE request started, and ONE already_running
            self.assertIn("started", statuses)
            self.assertIn("already_running", statuses)
            
            # Both requests received the EXACT SAME run_id
            self.assertEqual(run_ids[0], run_ids[1])

    @patch('src.api.server.requests.get', side_effect=mock_preflight_get)
    @patch('src.api.server.reserve_running_analysis')
    @patch('src.api.server.requests.post')
    def test_4_completed_and_failed_runs_do_not_block(self, mock_post, mock_reserve, mock_get):
        mock_post.return_value = MagicMock(status_code=204)
        
        # Scenario: Previous run was COMPLETED. Reserve returns is_new = True
        mock_reserve.return_value = (True, {"id": "1002", "status": "RUNNING", "repository": "owner/repo"})
        res1 = client.post("/api/github/repos/owner/repo/run-analysis")
        self.assertEqual(res1.json()["status"], "started")
        self.assertEqual(res1.json()["run_id"], "1002")

        # Scenario: Previous run was FAILED. Reserve returns is_new = True
        mock_reserve.return_value = (True, {"id": "1003", "status": "RUNNING", "repository": "owner/repo"})
        res2 = client.post("/api/github/repos/owner/repo/run-analysis")
        self.assertEqual(res2.json()["status"], "started")
        self.assertEqual(res2.json()["run_id"], "1003")

    @patch('src.api.server.requests.get', side_effect=mock_preflight_get)
    @patch('src.api.server.fail_analysis_run')
    @patch('src.api.server.reserve_running_analysis')
    @patch('src.api.server.requests.post')
    def test_5_failed_dispatch_marks_run_failed(self, mock_post, mock_reserve, mock_fail, mock_get):
        mock_reserve.return_value = (True, {"id": "1004", "status": "RUNNING", "repository": "owner/repo"})
        # GitHub dispatch fails with HTTP 500
        mock_post.return_value = MagicMock(
            status_code=500,
            headers={},
            json=MagicMock(return_value={"message": "Internal Server Error"}),
        )
        
        res = client.post("/api/github/repos/owner/repo/run-analysis")
        self.assertEqual(res.status_code, 502)
        
        # Verify fail_analysis_run was called so run does not remain stuck in RUNNING
        mock_fail.assert_called_once()

if __name__ == '__main__':
    unittest.main()
