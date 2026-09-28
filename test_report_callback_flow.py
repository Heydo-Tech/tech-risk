import os
import sys
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import src.api.server as server
from src.api.server import app


client = TestClient(app)


def report_payload(finding_id="f-callback"):
    return {
        "repo": "owner/repo",
        "summary": {"security": {"status": "COMPLETED", "count": 1}},
        "findings": [{"finding_id": finding_id, "severity": "HIGH"}],
    }


def running_run():
    return {
        "id": 801,
        "repository": "owner/repo",
        "branch": "main",
        "commit_sha": None,
        "workflow_run_id": None,
        "status": "RUNNING",
        "started_at": "2026-09-28T10:00:00+00:00",
        "completed_at": None,
        "error_message": None,
        "workflow_url": "https://github.com/owner/repo/actions",
        "report": {},
        "total_findings": 0,
    }


class TestReportCallbackFlow(unittest.TestCase):
    def setUp(self):
        self.old_secret = server.ANALYSIS_SECRET
        server.ANALYSIS_SECRET = "unit-test-secret"

    def tearDown(self):
        server.ANALYSIS_SECRET = self.old_secret

    def auth_headers(self):
        return {"Authorization": "Bearer unit-test-secret"}

    @patch("src.api.server.complete_analysis_run_report")
    def test_successful_report_callback_marks_running_completed(self, mock_complete):
        completed = {
            **running_run(),
            "status": "COMPLETED",
            "completed_at": "2026-09-28T10:05:00+00:00",
            "workflow_run_id": "123456",
            "report": report_payload(),
            "total_findings": 1,
        }
        mock_complete.return_value = completed

        res = client.post(
            "/api/analysis/runs/801/report",
            headers=self.auth_headers(),
            json={
                "repository": "owner/repo",
                "branch": "main",
                "commit_sha": "abc123",
                "workflow_run_id": "123456",
                "status": "COMPLETED",
                "report": report_payload(),
            },
        )

        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertTrue(body["success"])
        self.assertEqual(body["run_id"], 801)
        self.assertEqual(body["status"], "COMPLETED")
        self.assertEqual(body["completed_at"], "2026-09-28T10:05:00+00:00")
        mock_complete.assert_called_once()
        self.assertEqual(mock_complete.call_args.args[1], 801)
        self.assertEqual(mock_complete.call_args.args[2], report_payload())
        self.assertEqual(mock_complete.call_args.kwargs["repository"], "owner/repo")
        self.assertEqual(mock_complete.call_args.kwargs["workflow_run_id"], "123456")

    @patch("src.api.server.complete_analysis_run_report")
    def test_duplicate_report_callback_is_idempotent(self, mock_complete):
        completed = {
            **running_run(),
            "status": "COMPLETED",
            "completed_at": "2026-09-28T10:05:00+00:00",
            "report": report_payload("f-existing"),
            "total_findings": 1,
        }
        mock_complete.return_value = completed

        for _ in range(2):
            res = client.post(
                "/api/analysis/runs/801/report",
                headers=self.auth_headers(),
                json={"repository": "owner/repo", "report": report_payload("f-existing")},
            )
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.json()["status"], "COMPLETED")

        self.assertEqual(mock_complete.call_count, 2)

    @patch("src.api.server.complete_analysis_run_report")
    def test_repository_validation_error_is_rejected(self, mock_complete):
        mock_complete.side_effect = ValueError(
            "Analysis run 801 belongs to repository 'owner/repo', not 'other/repo'"
        )

        res = client.post(
            "/api/analysis/runs/801/report",
            headers=self.auth_headers(),
            json={"repository": "other/repo", "report": report_payload()},
        )

        self.assertEqual(res.status_code, 409)
        self.assertIn("belongs to repository", res.json()["detail"])

    @patch("src.api.server.complete_analysis_run_report")
    def test_missing_or_invalid_secret_is_rejected(self, mock_complete):
        res = client.post(
            "/api/analysis/runs/801/report",
            json={"repository": "owner/repo", "report": report_payload()},
        )

        self.assertEqual(res.status_code, 403)
        mock_complete.assert_not_called()

        res = client.post(
            "/api/analysis/runs/801/report",
            headers={"Authorization": "Bearer wrong-secret"},
            json={"repository": "owner/repo", "report": report_payload()},
        )

        self.assertEqual(res.status_code, 403)
        mock_complete.assert_not_called()

    @patch("src.api.server.complete_analysis_run_report")
    def test_nonexistent_run_is_rejected(self, mock_complete):
        mock_complete.side_effect = ValueError("Analysis run 999 was not found")

        res = client.post(
            "/api/analysis/runs/999/report",
            headers=self.auth_headers(),
            json={"repository": "owner/repo", "report": report_payload()},
        )

        self.assertEqual(res.status_code, 404)
        self.assertIn("not found", res.json()["detail"])

    @patch("src.api.server.complete_analysis_run_report")
    def test_callback_failure_does_not_fake_completed_run(self, mock_complete):
        mock_complete.side_effect = RuntimeError("database unavailable")

        res = client.post(
            "/api/analysis/runs/801/report",
            headers=self.auth_headers(),
            json={"repository": "owner/repo", "report": report_payload()},
        )

        self.assertEqual(res.status_code, 500)
        self.assertIn("Failed to persist analysis report", res.json()["detail"])
        mock_complete.assert_called_once()

    @patch("src.api.server.complete_analysis_run_report")
    def test_invalid_report_schema_is_rejected(self, mock_complete):
        res = client.post(
            "/api/analysis/runs/801/report",
            headers=self.auth_headers(),
            json={"repository": "owner/repo", "report": {"repo": "owner/repo"}},
        )

        self.assertEqual(res.status_code, 400)
        self.assertIn("report.json schema", res.json()["detail"])
        mock_complete.assert_not_called()


if __name__ == "__main__":
    unittest.main()
