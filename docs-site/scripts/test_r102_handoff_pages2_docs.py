"""Regression checks for round 1.0.2 handoff text on lane D pages."""

import unittest
from pathlib import Path


DOCS = Path(__file__).resolve().parents[1] / "content/docs"


def page(path):
    return (DOCS / path).read_text()


class R102HandoffPages2DocsTest(unittest.TestCase):
    def test_fg11_machine_policy_summary_missing(self):
        self.assertIn("| `machine_policy_summary_missing` | Windows |", page("enterprise/troubleshooting.mdx"))

    def test_fg11_stopped_service_verify_is_not_ready(self):
        row = next(line for line in page("enterprise/troubleshooting.mdx").splitlines()
                   if line.startswith("| `not_ready` | Windows |"))
        self.assertIn("`verify` also reports it", row)

    def test_fg11_rule_pack_preflight_grant(self):
        row = next(line for line in page("enterprise/troubleshooting.mdx").splitlines()
                   if line.startswith("| `rule_pack_unreadable` | Windows |"))
        self.assertIn("Setup's config preflight", row)
        self.assertIn("service's derived SID", row)

    def test_fg11_scanner_trust_and_judge(self):
        text = page("enterprise/troubleshooting.mdx")
        self.assertIn("folder or executable is writable by a non-administrator", text)
        self.assertIn("| `scanner_judge_missing` | Windows |", text)
        self.assertIn("`Scanners:` shows `judge none`", text)

    def test_fg11_secret_remove_requires_readable_config(self):
        text = page("enterprise/configuration.mdx")
        self.assertIn("refuses when it cannot read the installed config", text)

    def test_fg11_setup_upgrade_file_held(self):
        text = page("enterprise/troubleshooting.mdx")
        self.assertIn("Setup upgrade says another program holds a file open", text)

    def test_fg08_update_keeps_running_sessions_enforced(self):
        section = page("enterprise/tetragon.mdx").split(
            "5. **Restart agent sessions after enforce starts.**", 1
        )[1].split("The controls compile", 1)[0]
        self.assertIn("old controls policy\n   stays loaded and enforcing", section)
        self.assertNotIn("A planned follow-up", section)

    def test_fg08_predate_troubleshooting_excludes_self_update(self):
        tetragon = page("enterprise/tetragon.mdx")
        table = page("enterprise/troubleshooting.mdx")
        self.assertIn("enforce turned on or Tetragon restarted", tetragon)
        row = next(line for line in table.splitlines() if line.startswith("| `kernel_sessions_predate_controls`"))
        self.assertIn("old controls policy enforcing", row)
        self.assertNotIn("after an agent's own update", row)

    def test_fg08_limit_keeps_old_controls(self):
        section = page("enterprise/tetragon.mdx").split("## Reference", 1)[1]
        self.assertIn("old controls policy enforcing", section)
        self.assertNotIn("A planned follow-up", section)

    def test_fg08_lifecycle_retains_old_policy(self):
        row = next(line for line in page("enterprise/tetragon.mdx").splitlines()
                   if line.startswith("| An agent updates itself |"))
        self.assertIn("removed when the last one exits", row)
        self.assertNotIn("A planned follow-up", row)


if __name__ == "__main__":
    unittest.main()
