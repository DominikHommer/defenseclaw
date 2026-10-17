"""Regression checks for the 1.0.3 B-34 documentation corrections."""

import unittest
from pathlib import Path


DOCS = Path(__file__).resolve().parents[1] / "content/docs"
REPO = Path(__file__).resolve().parents[2]


def page(name):
    return " ".join((DOCS / name).read_text().split())


class R103B34DocsTest(unittest.TestCase):
    def test_issue_1264_reason_code_is_required_for(self):
        for rel in ("docs/OPENSHELL_SANDBOX_EVENTS.md", "schemas/telemetry/v8/operations.yaml",
                    "internal/audit/sandbox_policy_v8.go", "internal/audit/sandbox_policy_v8_test.go"):
            self.assertNotIn("required_group", (REPO / rel).read_text(), rel)

    def test_issue_1218_ssh_only_mac_users_unsupported(self):
        text = page("enterprise/sandboxes.mdx")
        self.assertIn("Macs where a user only signs in over SSH (unsupported)", text)
        self.assertIn("DefenseClaw does not support sandboxes for an SSH-only macOS account", text)

    def test_gap_0360_landlock_is_an_abi_not_a_kernel_version(self):
        for rel in ("enterprise/sandboxes.mdx", "enterprise/linux.mdx", "sandboxes/index.mdx"):
            self.assertNotIn("Landlock (kernel 6.2 or newer)", page(rel), rel)
        self.assertIn("Landlock ABI 3 or newer", page("sandboxes/linux.mdx"))

    def test_gap_0453_pin_is_not_applied_to_windows_profiles(self):
        text = page("policies/admission.mdx")
        self.assertIn("This per-copy check is for Linux and macOS", text)

    def test_gap_0377_0659_max_tokens_limits_named(self):
        self.assertIn("`max_completion_tokens`", page("connectors/zeptoclaw.mdx"))
        self.assertIn("`max_completion_tokens`", page("connectors/hermes.mdx"))

    def test_gap_0586_group_row_precision(self):
        text = page("guardrail/user-and-group-policies.mdx")
        self.assertIn("A numeric group id matches only while no name answers for that group", text)
        self.assertIn("this bare-name match runs on every host that has no Windows SID resolver", text)
        self.assertIn("names that contain `@` are skipped", text)

    def test_gap_0636_scenario_names_the_threshold(self):
        text = (REPO / "docs-site/data/policy-scenarios.json").read_text()
        self.assertIn("alert threshold MEDIUM", text)


if __name__ == "__main__":
    unittest.main()
