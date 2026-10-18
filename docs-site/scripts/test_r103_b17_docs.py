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
        self.assertIn("which records no package receipt", text)

    def test_1101_windows_event_ids(self):
        text = page("enterprise/operations.mdx")
        self.assertIn("`/ensure` writes 111 or 112 instead", text)

    def test_1101_admission_managed_alternative(self):
        text = (DOCS / "policies/admission.mdx").read_text()
        self.assertIn("For a per-user installation, read the compiled result", text)
        self.assertIn("installed `defenseclaw` launcher accepts only `sandbox` commands", text)
        self.assertIn("The managed Windows CLI has no `config get`", text)
        self.assertIn("A standard account is refused", text)
        self.assertIn("sudo /opt/defenseclaw/bin/defenseclaw-gateway policy evaluate --target-type skill --target-name risky-skill", text)
        self.assertIn("sudo /opt/defenseclaw/bin/defenseclaw-gateway policy show", text)
        self.assertNotIn("sudo defenseclaw-gateway policy", text)
        self.assertEqual(text.count("defenseclaw.exe' policy evaluate"), 1)
        self.assertEqual(text.count("defenseclaw.exe' policy show"), 1)
        self.assertIn(
            "--severity HIGH --findings 3\n```\n\n```text\n{\n  \"verdict\": \"rejected\"",
            text,
        )

    def test_known_limits_documented(self):
        self.assertIn("**Known limit.**", page("policies/defaults.mdx"))
        self.assertIn("do not yet check who owns the gateway port", page("enterprise/secure-client.mdx"))
        self.assertIn("pull <name> --apply` to merge them into your host project", page("sandboxes/guide.mdx"))
        self.assertNotIn("Current install output also says", page("reference/sandbox-cli.mdx"))

    def test_group_test_followups(self):
        self.assertIn("Windows Setup results report `policy`", page("enterprise/lifecycle.mdx"))
        self.assertIn("do not include a `changes` list", page("enterprise/lifecycle.mdx"))
        self.assertIn("five-minute interval starts at its first launch", page("enterprise/enrollment.mdx"))
        for rel in ("enterprise/threat-model.mdx", "connectors/claudecode.mdx"):
            text = page(rel)
            self.assertIn("without a pre-tool hook", text)
            self.assertIn("Guardrails cover the actions the agent takes", text)

    def test_1229_foreign_sandboxes_list_and_enforcement(self):
        text = page("enterprise/sandboxes.mdx")
        self.assertIn("A foreign sandbox has no registration, so it is absent from this list", text)
        self.assertIn("Managed `foreign_sandboxes` controls whether it is stopped or reported", text)
        self.assertNotIn("Foreign sandboxes are audit-only", text)
