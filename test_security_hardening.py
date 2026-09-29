import inspect
import unittest
from types import SimpleNamespace

import src.core.recheck as recheck


class TestSecurityHardening(unittest.TestCase):
    def test_repository_relative_path_is_validated_without_disk_access(self):
        self.assertEqual(recheck.validate_recheck_file_path("src/api/server.py"), "src/api/server.py")
        with self.assertRaises(ValueError):
            recheck.validate_recheck_file_path("../../../etc/passwd")
        with self.assertRaises(ValueError):
            recheck.validate_recheck_file_path("src\\server.py")

    def test_dispatch_data_has_no_shell_or_clone_execution(self):
        request = SimpleNamespace(repository="Heydo-Tech/dakiya.apnimandi.us", owner=None, name=None, tool="deslint", rule_id="no-console", file="src/App.jsx", line=1, line_end=None, commit_sha="a" * 40)
        _, inputs = recheck.build_recheck_dispatch("finding-1", request, "11111111-1111-4111-8111-111111111111")
        self.assertEqual(inputs["recheck_tool"], "deslint")
        source = inspect.getsource(recheck)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("clone_repo", source)


if __name__ == "__main__":
    unittest.main()
