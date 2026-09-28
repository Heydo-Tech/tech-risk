import unittest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
import sys
import os
import json
import base64

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.api.server import app
from src.storage.postgres import (
    reserve_running_analysis, complete_analysis_run, fail_analysis_run, get_current_run
)

# Mock DB layer for tests
import src.api.server
mock_db = {}
mock_runs = {}
mock_run_counter = 500

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

class TestPhase4Persistence(unittest.TestCase):
    
    def setUp(self):
        mock_db.clear()
        mock_runs.clear()
        
    @patch('src.api.server.requests.get', side_effect=mock_preflight_get)
    @patch('src.api.server.reserve_running_analysis')
    def test_1_atomic_reservation_and_duplicate_prevention(self, mock_reserve, mock_get):
        mock_db["conn"] = {"username": "user", "token": "ghp_valid"}
        
        # 1. First request reserves new run
        mock_reserve.return_value = (True, {"id": 501, "status": "RUNNING", "repository": "owner/repo", "branch": "main"})
        
        # Simulate trigger run
        with patch('src.api.server.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=204) # successful workflow_dispatch
            
            res1 = client.post("/api/github/repos/owner/repo/run-analysis")
            self.assertEqual(res1.status_code, 200)
            data1 = res1.json()
            self.assertEqual(data1["status"], "started")
            self.assertEqual(data1["run_id"], "501")

        # 2. Second concurrent request tries to reserve while RUNNING
        mock_reserve.return_value = (False, {"id": 501, "status": "RUNNING", "repository": "owner/repo", "branch": "main"})
        
        res2 = client.post("/api/github/repos/owner/repo/run-analysis")
        self.assertEqual(res2.status_code, 200)
        data2 = res2.json()
        self.assertEqual(data2["status"], "already_running")
        self.assertEqual(data2["run_id"], "501")
        self.assertIn("already running", data2["message"])

    @patch('src.api.server.complete_analysis_run')
    def test_2_complete_analysis_callback(self, mock_complete):
        report_payload = {
            "repo": "owner/repo",
            "findings": [{"finding_id": "f-01", "severity": "HIGH"}]
        }
        res = client.post(
            "/api/analysis/runs/501/complete",
            json={"report": report_payload, "commit_sha": "abc501"},
            headers={"secret": "dev_secret_key_1234"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "COMPLETED")
        mock_complete.assert_called_once()

    @patch('src.api.server.fail_analysis_run')
    def test_3_failed_analysis_callback(self, mock_fail):
        res = client.post(
            "/api/analysis/runs/501/failed",
            json={"error_message": "Scanner process timed out"},
            headers={"secret": "dev_secret_key_1234"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "FAILED")
        mock_fail.assert_called_once()

    @patch('src.api.server.get_current_run')
    def test_4_current_run_api(self, mock_get_current):
        mock_get_current.return_value = {
            "id": 501,
            "repository": "owner/repo",
            "status": "RUNNING",
            "started_at": "2026-09-24T19:00:00Z",
            "workflow_url": "https://github.com/owner/repo/actions"
        }
        res = client.get("/api/github/repos/owner/repo/current-run")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "RUNNING")
        self.assertEqual(data["run"]["id"], 501)

if __name__ == '__main__':
    unittest.main()
