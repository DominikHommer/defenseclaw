"""Pin the copied-home plugin cleanup wording for the 1.0.2 release."""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs-site/content/docs"


class Delta39DocsTest(unittest.TestCase):
    def test_enrollment_explains_copied_plugin_receipts(self):
        text = (DOCS / "enterprise/enrollment.mdx").read_text()
        self.assertIn("A copied OpenCode or Amp plugin receipt cannot direct one\nhome's cleanup into the other home", text)
        self.assertIn("For those plugins, the record ends only when the current home's plugin is\ngone and either the recorded home is definitely gone or its plugin is also\ngone", text)
        self.assertIn("An edited plugin that still contains\nDefenseClaw code keeps the record; the warning names its path", text)
        self.assertIn("Remove\nDefenseClaw's entries from that plugin and rerun", text)
        self.assertNotIn("The record ends when the recorded home is definitely gone or\nboth cleanups succeed", text)


if __name__ == "__main__":
    unittest.main()
