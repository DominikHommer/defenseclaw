"""Pin the re-homed per-user cleanup wording for the 1.0.2 release."""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs-site/content/docs"


class Delta39DocsTest(unittest.TestCase):
    def test_enrollment_explains_reported_paths(self):
        text = " ".join((DOCS / "enterprise/enrollment.mdx").read_text().split())
        self.assertIn("Each user's cleanup worker reports the agent config paths it found or edited", text)
        self.assertIn("when removal succeeds, the guardian retries that home's cleanup once", text)
        self.assertIn("every reported path lies in the home its worker cleaned", text)
        self.assertIn("the current home has no DefenseClaw entries for that agent", text)
        self.assertIn("An absent report, a path outside the home, or entries left in the current home keep the record", text)
        self.assertIn("delete a stale copied receipt in its `.defenseclaw/connector_backups/` folder", text)
        self.assertIn("An operator-edited plugin left in the recorded home is left for the operator and does not alone keep the record", text)
        self.assertNotIn("both cleanups succeed", text)
        self.assertNotIn("An edited plugin that still contains DefenseClaw code keeps the record", text)

    def test_troubleshooting_explains_copied_receipt_and_remedy(self):
        text = " ".join((DOCS / "enterprise/troubleshooting.mdx").read_text().split())
        self.assertIn("A copied backup receipt can name a config path in another home", text)
        self.assertIn("If a reported path still lies outside the home its worker cleaned, a report is absent, or the current home still has DefenseClaw entries, the cleanup row stays", text)
        self.assertIn("The row ends only when every path reported by each worker lies inside the home it cleaned and the current-home worker found no DefenseClaw entries left", text)
        self.assertIn("delete a stale copied receipt under its `.defenseclaw/connector_backups/<agent>/`", text)
        self.assertNotIn("the guardian cleans its current home as that user and also cleans its old home", text)


if __name__ == "__main__":
    unittest.main()
