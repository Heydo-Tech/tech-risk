import inspect
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

import src.api.server as server
from src.core.recheck import build_recheck_dispatch, normalize_github_repository


REPOSITORY = "Heydo-Tech/dakiya.apnimandi.us"
FINDING = {"finding_id": "finding-1", "detected_by": ["semgrep"], "rule_id": "rule.one"}


def _response(status_code, payload=None, text=""):
    response = MagicMock(status_code=status_code, text=text)
    response.json.return_value = payload or {}
    response.headers = {}
    return response


class TestRecheckRepositoryIdentity(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(server.app)
        self.previous_secret = server.ANALYSIS_SECRET
        server.ANALYSIS_SECRET = "test-analysis-secret"

    def tearDown(self):
        server.ANALYSIS_SECRET = self.previous_secret

    def test_repository_normalization_is_canonical(self):
        for identity in (
            normalize_github_repository(REPOSITORY),
            normalize_github_repository(owner="Heydo-Tech", name="dakiya.apnimandi.us"),
            normalize_github_repository("https://github.com/Heydo-Tech/dakiya.apnimandi.us.git"),
        ):
            self.assertEqual(identity["owner"], "Heydo-Tech")
            self.assertEqual(identity["name"], "dakiya.apnimandi.us")
            self.assertEqual(identity["full_name"], REPOSITORY)
            self.assertNotIn("Heydo-Tech/Heydo-Tech", identity["full_name"])

    def test_dispatch_builder_never_clones_or_imports_git_helpers(self):
        request = SimpleNamespace(repository=REPOSITORY, owner=None, name=None, tool="semgrep", rule_id="rule.one", file="src/app.py", line=10, line_end=12, commit_sha="abc123")
        identity, inputs = build_recheck_dispatch("finding-1", request)
        self.assertEqual(identity["full_name"], REPOSITORY)
        self.assertEqual(inputs["recheck_file_path"], "src/app.py")
        self.assertNotIn("clone_repo", inspect.getsource(__import__("src.core.recheck", fromlist=["*"])))

    @patch("src.api.server.update_finding_lifecycle")
    @patch("src.api.server.get_finding_lifecycle", return_value={"status": "OPEN"})
    @patch("src.api.server._finding_for_recheck", return_value=FINDING)
    @patch("src.api.server.get_github_connection", return_value={"token": "ghp_not_exposed"})
    @patch("src.api.server.requests.post")
    @patch("src.api.server.requests.get")
    def test_dispatches_strict_workflow_inputs(self, get, post, _connection, _finding, _lifecycle, update):
        get.side_effect = [_response(200, {"default_branch": "main"}), _response(200, {"content": "d29ya2Zsb3dfZGlzcGF0Y2g6CiAgcmVjaGVja19maW5kaW5nX2lkOg=="})]
        post.return_value = _response(204)
        response = self.client.post("/api/findings/finding-1/recheck", json={"repository": REPOSITORY, "tool": "semgrep", "rule_id": "rule.one", "file": "src/app.py", "line": 10, "line_end": 12, "commit_sha": "abc123"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "RECHECKING")
        self.assertNotIn("ghp_not_exposed", response.text)
        self.assertEqual(post.call_args.args[0], f"https://api.github.com/repos/{REPOSITORY}/actions/workflows/code-analysis.yml/dispatches")
        self.assertEqual(post.call_args.kwargs["json"], {"ref": "main", "inputs": {"recheck_finding_id": "finding-1", "recheck_tool": "semgrep", "recheck_rule_id": "rule.one", "recheck_file_path": "src/app.py", "recheck_line_start": "10", "recheck_line_end": "12", "recheck_commit_sha": "abc123"}})
        self.assertEqual(update.call_args.kwargs["status"], "RECHECKING")

    @patch("src.api.server.update_finding_lifecycle")
    @patch("src.api.server.get_finding_lifecycle", return_value={"status": "OPEN"})
    @patch("src.api.server._finding_for_recheck", return_value=FINDING)
    @patch("src.api.server.get_github_connection", return_value={"token": "ghp_not_exposed"})
    @patch("src.api.server.requests.post", return_value=_response(403, {"message": "forbidden"}))
    @patch("src.api.server.requests.get")
    def test_failed_dispatch_returns_finding_to_open(self, get, _post, _connection, _finding, _lifecycle, update):
        get.side_effect = [_response(200, {"default_branch": "main"}), _response(200, {"content": "d29ya2Zsb3dfZGlzcGF0Y2g6CiAgcmVjaGVja19maW5kaW5nX2lkOg=="})]
        response = self.client.post("/api/findings/finding-1/recheck", json={"repository": REPOSITORY, "tool": "semgrep", "rule_id": "rule.one", "file": "src/app.py"})
        self.assertEqual(response.status_code, 403)
        statuses = [call.kwargs["status"] for call in update.call_args_list]
        self.assertEqual(statuses, ["RECHECKING", "OPEN"])
        self.assertNotIn("FIXED", statuses)
        self.assertNotIn("ghp_not_exposed", response.text)

    @patch("src.api.server.update_finding_lifecycle")
    @patch("src.api.server.get_finding_lifecycle", return_value={"status": "RECHECKING"})
    @patch("src.api.server._finding_for_recheck", return_value=FINDING)
    def test_authenticated_callback_persists_fixed(self, _finding, _lifecycle, update):
        response = self.client.post("/api/findings/finding-1/recheck-result", headers={"Authorization": "Bearer test-analysis-secret"}, json={"repository": REPOSITORY, "tool": "semgrep", "rule_id": "rule.one", "status": "FIXED"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "FIXED")
        self.assertEqual(update.call_args.kwargs["status"], "FIXED")

    @patch("src.api.server.update_finding_lifecycle")
    @patch("src.api.server.get_finding_lifecycle", return_value={"status": "RECHECKING"})
    @patch("src.api.server._finding_for_recheck", return_value=FINDING)
    def test_failed_callback_never_marks_fixed_and_is_authenticated(self, _finding, _lifecycle, update):
        forbidden = self.client.post("/api/findings/finding-1/recheck-result", json={"repository": REPOSITORY, "tool": "semgrep", "rule_id": "rule.one", "status": "FIXED"})
        self.assertEqual(forbidden.status_code, 403)
        response = self.client.post("/api/findings/finding-1/recheck-result", headers={"Authorization": "Bearer test-analysis-secret"}, json={"repository": REPOSITORY, "tool": "semgrep", "rule_id": "rule.one", "status": "FAILED"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "OPEN")
        self.assertEqual(update.call_args.kwargs["status"], "OPEN")

    @patch("src.api.server.update_finding_lifecycle")
    @patch("src.api.server.get_finding_lifecycle", return_value={"status": "FIXED", "verification_tool": "semgrep"})
    @patch("src.api.server._finding_for_recheck", return_value=FINDING)
    def test_duplicate_result_callback_is_idempotent(self, _finding, _lifecycle, update):
        response = self.client.post("/api/findings/finding-1/recheck-result", headers={"Authorization": "Bearer test-analysis-secret"}, json={"repository": REPOSITORY, "tool": "semgrep", "rule_id": "rule.one", "status": "FIXED"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["idempotent"])
        update.assert_not_called()

    def test_invalid_tool_and_path_traversal_are_rejected_before_github(self):
        invalid_tool = self.client.post("/api/findings/finding-1/recheck", json={"repository": REPOSITORY, "tool": "anything", "rule_id": "rule.one", "file": "src/app.py"})
        traversal = self.client.post("/api/findings/finding-1/recheck", json={"repository": REPOSITORY, "tool": "semgrep", "rule_id": "rule.one", "file": "../../secret.py"})
        self.assertEqual(invalid_tool.status_code, 400)
        self.assertEqual(traversal.status_code, 400)


if __name__ == "__main__":
    unittest.main()
