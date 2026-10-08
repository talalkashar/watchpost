import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class CiConfigurationTests(unittest.TestCase):
    def test_supported_python_matrix_and_required_checks(self):
        workflow = (ROOT / ".github/workflows/tests.yml").read_text()
        self.assertIn('python: ["3.11", "3.12", "3.13", "3.14"]', workflow)
        self.assertNotIn('"3.10"', workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("run: ./run_tests.sh", workflow)
        self.assertIn("pull_request:", workflow)
        self.assertIn("branches: [main]", workflow)
        actions = re.findall(r"uses: (actions/[^@]+)@([^ ]+)", workflow)
        self.assertEqual({name for name, _ in actions}, {"actions/checkout", "actions/setup-python"})
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{40}", revision) for _, revision in actions), actions)

    def test_readme_has_the_live_workflow_badge(self):
        readme = (ROOT / "README.md").read_text()
        badge = "https://github.com/talalkashar/watchpost/actions/workflows/tests.yml/badge.svg"
        target = "https://github.com/talalkashar/watchpost/actions/workflows/tests.yml"
        self.assertIn(f"[![tests]({badge})]({target})", readme)


if __name__ == "__main__":
    unittest.main()
