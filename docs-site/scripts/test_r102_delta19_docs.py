"""Managed registration alert and required-sandbox limit copy for 1.0.2."""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs-site/content/docs"


class Delta19DocsTest(unittest.TestCase):
    def test_enterprise_limit_and_admin_signal(self):
        text = (DOCS / "enterprise/sandboxes.mdx").read_text()
        self.assertIn("**A registration vouches for the account, not for a VM.** The managed", text)
        self.assertNotIn("That never loosens their\n  policy", text)
        self.assertIn("`sandbox.required_for` keeps normal host use", text)
        self.assertIn("deliberately fakes a running-sandbox registration", text)
        self.assertIn("no root-owned sandbox lifecycle service to vouch", text.lower())
        self.assertIn("the same account can also post lifecycle", text)
        self.assertIn("keep the `docker` group limited", text)
        self.assertIn("whose lifecycle records were dropped can show once", text.lower())
        for value in ("relay_without_guest", "running_without_guest", "Sandbox\nregistrations without a guest"):
            self.assertIn(value, text)

    def test_telemetry_and_guide_link(self):
        telemetry = (DOCS / "observability/sandbox-telemetry.mdx").read_text()
        guide = (DOCS / "sandboxes/guide.mdx").read_text()
        events = (ROOT / "docs/OPENSHELL_SANDBOX_EVENTS.md").read_text()
        for text in (telemetry, events):
            for value in ("log.sandbox.registration_without_guest", "relay_without_guest", "running_without_guest", "Sandbox registrations without a guest"):
                self.assertIn(value, text)
        self.assertIn("/docs/enterprise/sandboxes#require-sandboxes", guide)


if __name__ == "__main__":
    unittest.main()
