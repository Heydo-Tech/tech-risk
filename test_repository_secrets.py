import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from src.api import server


client = TestClient(server.app)
SECRET_VALUE = "test-secret-value-never-returned"


def github_response(status_code, body=None):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = body or {}
    response.text = str(body or "")
    response.headers = {}
    return response


class TestRepositorySecrets(unittest.TestCase):
    def setUp(self):
        self.connection = {"token": "ghp_test_token", "username": "tester"}
        self.managed = []
        self.onboarding = {}
        self.patches = [
            patch.object(server, "get_github_connection", side_effect=lambda _: self.connection),
            patch.object(server, "get_managed_repos", side_effect=lambda _: self.managed),
            patch.object(server, "get_repo_onboarding", side_effect=lambda _, name: self.onboarding.get(name)),
            patch.object(server, "_encrypt_github_actions_secret", return_value="encrypted-value"),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()

    @staticmethod
    def _public_key():
        return github_response(200, {"key_id": "key-id", "key": "ZmFrZS1wdWJsaWMta2V5"})

    @patch("src.api.server.requests.put")
    @patch("src.api.server.requests.get")
    def test_valid_custom_name_current_repository_is_configured(self, mock_get, mock_put):
        mock_get.side_effect = [github_response(404, {"message": "Not found"}), self._public_key()]
        mock_put.return_value = github_response(201)

        response = client.put(
            "/api/repositories/owner/repo/secrets/custom_key_7",
            json={"secret_value": SECRET_VALUE},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["secret_name"], "CUSTOM_KEY_7")
        self.assertEqual(response.json()["results"], [{"repository": "owner/repo", "status": "configured"}])
        self.assertNotIn(SECRET_VALUE, response.text)
        self.assertNotIn(SECRET_VALUE, str(mock_put.call_args))
        self.assertEqual(mock_put.call_args.kwargs["json"], {"encrypted_value": "encrypted-value", "key_id": "key-id"})
        self.assertIn("/repos/owner/repo/actions/secrets/CUSTOM_KEY_7", mock_put.call_args.args[0])

    def test_invalid_and_reserved_secret_names_are_rejected_before_github(self):
        for name in ("not valid", "1START", "GITHUB_TOKEN", "name-with-dash"):
            with self.subTest(name=name), patch("src.api.server.requests.get") as mock_get:
                response = client.put(f"/api/repositories/owner/repo/secrets/{name}", json={"secret_value": SECRET_VALUE})
                self.assertEqual(response.status_code, 400)
                mock_get.assert_not_called()

    @patch("src.api.server.requests.put")
    @patch("src.api.server.requests.get")
    def test_existing_secret_is_safely_updated_using_put(self, mock_get, mock_put):
        mock_get.side_effect = [github_response(200, {"name": "EXISTING"}), self._public_key()]
        mock_put.return_value = github_response(204)
        response = client.put("/api/repositories/owner/repo/secrets/EXISTING", json={"secret_value": SECRET_VALUE, "replace_existing": True})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["configured_count"], 1)
        self.assertEqual(mock_put.call_count, 1)

    @patch("src.api.server.requests.put")
    @patch("src.api.server.requests.get")
    def test_configured_secret_is_kept_without_a_mutation(self, mock_get, mock_put):
        mock_get.return_value = github_response(200, {"name": "EXISTING"})
        response = client.put("/api/repositories/owner/repo/secrets/EXISTING", json={"secret_value": SECRET_VALUE})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["results"], [{"repository": "owner/repo", "status": "kept"}])
        self.assertEqual(response.json()["kept_count"], 1)
        mock_put.assert_not_called()
        self.assertNotIn(SECRET_VALUE, response.text)

    def _set_onboarded_targets(self, *names):
        self.managed = [
            {"full_name": name, "owner": name.split("/")[0], "name": name.split("/")[1], "selected": True}
            for name in names
        ]
        self.onboarding = {name: {"status": "UP_TO_DATE"} for name in names}

    @patch("src.api.server.requests.put")
    @patch("src.api.server.requests.get")
    def test_multi_repository_success(self, mock_get, mock_put):
        self._set_onboarded_targets("owner/one", "owner/two")
        mock_get.side_effect = [github_response(404), self._public_key(), github_response(404), self._public_key()]
        mock_put.return_value = github_response(201)
        response = client.put("/api/repositories/secrets/CUSTOM_KEY/apply", json={"secret_value": SECRET_VALUE})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["configured_count"], 2)
        self.assertEqual(response.json()["rejected_count"], 0)
        self.assertEqual(mock_put.call_count, 2)

    @patch("src.api.server.requests.put")
    @patch("src.api.server.requests.get")
    def test_partial_failure_continues_and_redacts_secret(self, mock_get, mock_put):
        self._set_onboarded_targets("owner/one", "owner/two")
        mock_get.side_effect = [github_response(404), self._public_key(), github_response(403, {"message": SECRET_VALUE})]
        mock_put.return_value = github_response(201)
        response = client.put("/api/repositories/secrets/CUSTOM_KEY/apply", json={"secret_value": SECRET_VALUE})
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["configured_count"], 1)
        self.assertEqual(data["rejected_count"], 1)
        self.assertNotIn(SECRET_VALUE, response.text)
        self.assertIn("[REDACTED]", data["results"][1]["reason"])
        self.assertEqual(mock_put.call_count, 1)

    @patch("src.api.server.requests.put")
    @patch("src.api.server.requests.get")
    def test_bulk_configuration_keeps_existing_and_replaces_only_explicit_selection(self, mock_get, mock_put):
        self._set_onboarded_targets("owner/one", "owner/two")
        mock_get.side_effect = [
            github_response(200, {"name": "CUSTOM_KEY"}),
            github_response(200, {"name": "CUSTOM_KEY"}),
            self._public_key(),
        ]
        mock_put.return_value = github_response(201)
        response = client.put(
            "/api/repositories/secrets/CUSTOM_KEY/apply",
            json={"secret_value": SECRET_VALUE, "replace_existing": True, "replace_repositories": ["owner/two"]},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["results"][0]["status"], "kept")
        self.assertEqual(data["results"][1]["status"], "configured")
        self.assertEqual(mock_put.call_count, 1)
        self.assertIn("/repos/owner/two/actions/secrets/CUSTOM_KEY", mock_put.call_args.args[0])
        self.assertNotIn(SECRET_VALUE, response.text)

    @patch("src.api.server.requests.get")
    def test_all_failures_are_reported_without_aborting(self, mock_get):
        self._set_onboarded_targets("owner/one", "owner/two")
        mock_get.return_value = github_response(403, {"message": "Resource not accessible"})
        response = client.put("/api/repositories/secrets/CUSTOM_KEY/apply", json={"secret_value": SECRET_VALUE})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["configured_count"], 0)
        self.assertEqual(response.json()["rejected_count"], 2)
        self.assertEqual(mock_get.call_count, 2)

    @patch("src.api.server.requests.get")
    def test_github_401_403_404_are_safe_repository_results(self, mock_get):
        for status in (401, 403, 404):
            with self.subTest(status=status):
                mock_get.return_value = github_response(status, {"message": "GitHub diagnostic"})
                response = client.put("/api/repositories/owner/repo/secrets/CUSTOM_KEY", json={"secret_value": SECRET_VALUE})
                self.assertEqual(response.status_code, 200)
                result = response.json()["results"][0]
                self.assertEqual(result["status"], "rejected")
                self.assertIn(f"GitHub returned {status}", result["reason"])
                self.assertNotIn(SECRET_VALUE, response.text)

    @patch("src.api.server.requests.get")
    def test_github_api_request_failure_is_safe(self, mock_get):
        mock_get.side_effect = server.requests.RequestException("network failure")
        response = client.put("/api/repositories/owner/repo/secrets/CUSTOM_KEY", json={"secret_value": SECRET_VALUE})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["results"][0]["reason"], "GitHub secret metadata request failed")
        self.assertNotIn(SECRET_VALUE, response.text)

    def test_missing_github_connection_is_rejected(self):
        self.connection = None
        response = client.put("/api/repositories/owner/repo/secrets/CUSTOM_KEY", json={"secret_value": SECRET_VALUE})
        self.assertEqual(response.status_code, 401)
        self.assertNotIn(SECRET_VALUE, response.text)

    @patch("src.api.server.requests.get")
    def test_encryption_failure_does_not_call_secret_write(self, mock_get):
        mock_get.side_effect = [github_response(404), self._public_key()]
        with patch.object(server, "_encrypt_github_actions_secret", side_effect=RuntimeError("secret failure")), patch("src.api.server.requests.put") as mock_put:
            response = client.put("/api/repositories/owner/repo/secrets/CUSTOM_KEY", json={"secret_value": SECRET_VALUE})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["results"][0]["reason"], "Could not encrypt the repository secret")
        mock_put.assert_not_called()
        self.assertNotIn(SECRET_VALUE, response.text)

    @patch("src.api.server.requests.get")
    def test_secret_metadata_status_never_returns_values(self, mock_get):
        mock_get.return_value = github_response(200, {"name": "CUSTOM_KEY", "updated_at": "2026-09-29"})
        response = client.get("/api/repositories/owner/repo/secrets/custom_key/status")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "configured")
        self.assertNotIn("updated_at", response.text)


if __name__ == "__main__":
    unittest.main()
