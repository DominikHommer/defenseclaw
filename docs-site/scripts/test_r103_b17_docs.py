"""Regression checks for the 1.0.3 B-17 docs fixes."""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs-site/content/docs"


def page(rel):
    return " ".join((DOCS / rel).read_text().split())


class R103B17DocsTest(unittest.TestCase):
    def test_1264_events_doc_names_required_for(self):
        text = (ROOT / "docs/OPENSHELL_SANDBOX_EVENTS.md").read_text()
        self.assertNotIn("required_group", text)
        self.assertIn("such as `required_for`", text)

    def test_1100_macos_pkg_fails_on_port_held(self):
        text = page("enterprise/macos.mdx")
        self.assertNotIn("the pkg install still completes", text)
        self.assertIn("records no package receipt", text)

    def test_1101_windows_event_ids(self):
        text = page("enterprise/operations.mdx")
        self.assertIn("`/ensure` writes 111 or 112 instead", text)

    def test_1101_admission_managed_alternative(self):
        text = page("policies/admission.mdx")
        self.assertIn("are per-user commands", text)

    def test_known_limits_documented(self):
        self.assertIn("**Known limit.**", page("policies/defaults.mdx"))
        self.assertIn("do not yet check who owns the gateway port", page("enterprise/secure-client.mdx"))
        self.assertIn("before you switch drivers", page("sandboxes/guide.mdx"))

    def test_1229_foreign_sandboxes_audit_only(self):
        self.assertIn("Foreign sandboxes are audit-only", page("enterprise/sandboxes.mdx"))
