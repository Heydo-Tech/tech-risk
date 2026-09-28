import io
import json
import os
import sys
import unittest
import zipfile
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import src.api.server as server
from src.api.server import app


client = TestClient(app)


def make_response(status_code=200, payload=None, headers=None, content=b""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.json.return_value = payload if payload is not None else {}
    resp.content = content
    return resp


def make_report_zip(report_payload=None, include_report=True):
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w") as archive:
        if include_report:
            archive.writestr(
                "target-repo/report.json",
                json.dumps(report_payload or {"findings": [{"finding_id": "f-1", "severity": "HIGH"}]}),
            )
    return archive_bytes.getvalue()


def running_run(run_id=701):
    return {
        "id": run_id,
        "repository": "owner/repo",
        "branch": "main",
        "commit_sha": None,
        "workflow_run_id": None,
        "status": "RUNNING",
        "started_at": "2026-09-25T10:00:00+00:00",
        "completed_at": None,
        "error_message": None,
        "workflow_url": "https://github.com/owner/repo/actions",
        "report": None,
    }


class TestGitHubArtifactSync(unittest.TestCase):
    def setUp(self):
        self.token = "ghp_secret_sync_token_123"

    @patch("src.api.server.get_github_connection")
    @patch("src.api.server.get_current_run")
    @patch("src.api.server.complete_analysis_run")
    @patch("src.api.server.fail_analysis_run")
    @patch("src.api.server.requests.get")
    def test_successful_workflow_artifact_completes_running_run(
        self,
        mock_get,
        mock_fail,
        mock_complete,
        mock_current,
        mock_connection,
    ):
        report_payload = {
            "metadata": {"repository": "owner/repo"},
            "summary": {"security": {"status": "COMPLETED", "count": 1}},
            "findings": [{"finding_id": "f-1", "severity": "HIGH", "tool": "semgrep"}],
        }
        mock_connection.return_value = {"username": "user", "token": self.token}
        mock_current.side_effect = [
            running_run(701),
            {**running_run(701), "status": "COMPLETED", "workflow_run_id": "9001", "report": report_payload},
        ]
        mock_get.side_effect = [
            make_response(
                payload={
                    "workflow_runs": [
                        {
                            "id": 9001,
                            "status": "completed",
                            "conclusion": "success",
                            "created_at": "2026-09-25T10:01:00Z",
                            "head_sha": "abc123",
                            "head_branch": "main",
                        }
                    ]
                }
            ),
            make_response(
                payload={
                    "artifacts": [
                        {
                            "id": 3001,
                            "name": "repo-analysis-report-owner-repo-9001",
                            "expired": False,
                            "archive_download_url": "https://api.github.com/artifacts/3001/zip",
                        }
                    ]
                }
            ),
            make_response(content=make_report_zip(report_payload)),
        ]

        res = client.get("/api/github/repos/owner/repo/current-run")

        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "COMPLETED")
        mock_complete.assert_called_once()
        args = mock_complete.call_args.args
        kwargs = mock_complete.call_args.kwargs
        self.assertEqual(args[1], 701)
        self.assertEqual(args[2], report_payload)
        self.assertEqual(kwargs["workflow_run_id"], "9001")
        self.assertEqual(kwargs["commit_sha"], "abc123")
        mock_fail.assert_not_called()
        self.assertNotIn(self.token, str(res.json()))

    @patch("src.api.server.get_github_connection")
    @patch("src.api.server.get_current_run")
    @patch("src.api.server.complete_analysis_run")
    @patch("src.api.server.fail_analysis_run")
    @patch("src.api.server.requests.get")
    def test_naive_postgres_started_at_can_match_github_utc_run(
        self,
        mock_get,
        mock_fail,
        mock_complete,
        mock_current,
        mock_connection,
    ):
        report_payload = {
            "metadata": {"repository": "owner/repo"},
            "findings": [{"finding_id": "f-naive", "severity": "MEDIUM"}],
        }
        naive_started_run = running_run(705)
        naive_started_run["started_at"] = "2026-09-25T10:00:00"
        mock_connection.return_value = {"username": "user", "token": self.token}
        mock_current.side_effect = [
            naive_started_run,
            {**naive_started_run, "status": "COMPLETED", "workflow_run_id": "9005", "report": report_payload},
        ]
        mock_get.side_effect = [
            make_response(
                payload={
                    "workflow_runs": [
                        {
                            "id": 9005,
                            "status": "completed",
                            "conclusion": "success",
                            "created_at": "2026-09-25T10:01:00Z",
                            "head_sha": "def456",
                            "head_branch": "main",
                        }
                    ]
                }
            ),
            make_response(
                payload={
                    "artifacts": [
                        {
                            "id": 3005,
                            "name": "repo-analysis-report-owner-repo-9005",
                            "expired": False,
                            "archive_download_url": "https://api.github.com/artifacts/3005/zip",
                        }
                    ]
                }
            ),
            make_response(content=make_report_zip(report_payload)),
        ]

        res = client.get("/api/github/repos/owner/repo/current-run")

        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "COMPLETED")
        mock_complete.assert_called_once()
        self.assertEqual(mock_complete.call_args.args[1], 705)
        self.assertEqual(mock_complete.call_args.kwargs["workflow_run_id"], "9005")
        mock_fail.assert_not_called()

    @patch("src.api.server.get_github_connection")
    @patch("src.api.server.get_current_run")
    @patch("src.api.server.complete_analysis_run")
    @patch("src.api.server.fail_analysis_run")
    @patch("src.api.server.requests.get")
    def test_failed_workflow_conclusion_marks_run_failed(
        self,
        mock_get,
        mock_fail,
        mock_complete,
        mock_current,
        mock_connection,
    ):
        mock_connection.return_value = {"username": "user", "token": self.token}
        mock_current.side_effect = [running_run(702), {**running_run(702), "status": "FAILED"}]
        mock_get.return_value = make_response(
            payload={
                "workflow_runs": [
                    {
                        "id": 9002,
                        "status": "completed",
                        "conclusion": "failure",
                        "created_at": "2026-09-25T10:01:00Z",
                    }
                ]
            }
        )

        res = client.get("/api/github/repos/owner/repo/current-run")

        self.assertEqual(res.status_code, 200)
        mock_fail.assert_called_once()
        self.assertEqual(mock_fail.call_args.args[1], 702)
        self.assertIn("conclusion failure", mock_fail.call_args.args[2])
        mock_complete.assert_not_called()

    @patch("src.api.server.get_github_connection")
    @patch("src.api.server.get_current_run")
    @patch("src.api.server.complete_analysis_run")
    @patch("src.api.server.fail_analysis_run")
    @patch("src.api.server.requests.get")
    def test_success_without_report_artifact_marks_run_failed(
        self,
        mock_get,
        mock_fail,
        mock_complete,
        mock_current,
        mock_connection,
    ):
        mock_connection.return_value = {"username": "user", "token": self.token}
        mock_current.side_effect = [running_run(703), {**running_run(703), "status": "FAILED"}]
        mock_get.side_effect = [
            make_response(
                payload={
                    "workflow_runs": [
                        {
                            "id": 9003,
                            "status": "completed",
                            "conclusion": "success",
                            "created_at": "2026-09-25T10:01:00Z",
                        }
                    ]
                }
            ),
            make_response(payload={"artifacts": []}),
        ]

        res = client.get("/api/github/repos/owner/repo/current-run")

        self.assertEqual(res.status_code, 200)
        mock_fail.assert_called_once()
        self.assertEqual(mock_fail.call_args.args[1], 703)
        self.assertIn("no repo-analysis-report artifact", mock_fail.call_args.args[2])
        mock_complete.assert_not_called()

    @patch("src.api.server.complete_analysis_run")
    def test_wrong_run_id_complete_callback_returns_404(self, mock_complete):
        mock_complete.side_effect = ValueError("Analysis run 999 was not found")

        res = client.post(
            "/api/analysis/runs/999/complete",
            json={"report": {"findings": []}},
            headers={"secret": "dev_secret_key_1234"},
        )

        self.assertEqual(res.status_code, 404)
        self.assertIn("Analysis run 999 was not found", res.json()["detail"])

    @patch("src.api.server.complete_analysis_run")
    def test_empty_report_complete_callback_returns_error(self, mock_complete):
        mock_complete.side_effect = ValueError("Cannot complete analysis run without a non-empty report")

        res = client.post(
            "/api/analysis/runs/704/complete",
            json={"report": {}},
            headers={"secret": "dev_secret_key_1234"},
        )

        self.assertEqual(res.status_code, 400)
        self.assertIn("non-empty report", res.json()["detail"])


if __name__ == "__main__":
    unittest.main()
