"""Regression checks for round 1.0.2 handoff text on lane D pages."""

import unittest
from pathlib import Path


DOCS = Path(__file__).resolve().parents[1] / "content/docs"


def page(path):
    return (DOCS / path).read_text()


class R102HandoffPages2DocsTest(unittest.TestCase):
    def test_pr886_remote_scanner_empty_rules_use_connection_policy(self):
        text = page("guardrail/index.mdx")
        self.assertIn("an unset or empty\n`cisco_ai_defense.enabled_rules` sends no", text)
        self.assertIn("A nonempty operator list is sent in\nthe order configured", text)
        self.assertIn("former implicit 12-rule list", text)

    def test_fg02_relative_scanner_policy_path(self):
        row = next(line for line in page("reference/migrate-v9.mdx").splitlines()
                   if line.startswith("| `policy: <path to a file>` |"))
        self.assertIn("including a file named `custom`", row)
        self.assertIn("pinned by its absolute path", row)
        self.assertNotIn("becomes `quiet`", row)

    def test_fg02_duplicate_custom_providers_merge(self):
        section = page("reference/migrate-v9.mdx").split("### Custom providers", 1)[1]
        self.assertIn("lists are unioned and the overlay's\nvalues win", section)
        self.assertIn("`migration-v9.json` notes each merged provider", section)

    def test_fg01_rollback_restores_data_and_prunes_hooks(self):
        text = page("get-started/upgrade.mdx")
        self.assertIn("comes back when you run `defenseclaw rollback`\nagain", text)
        self.assertIn("on every `defenseclaw upgrade`, DefenseClaw removes only\nits own hook entries", text)

    def test_fg16_linked_macos_scan_root_is_partial(self):
        discovery = page("ai-discovery.mdx")
        macos = page("enterprise/macos.mdx")
        self.assertIn("a root reached through a link into a protected folder is skipped", discovery)
        self.assertIn("package scan root reached through\na link into one of these folders", macos)
        self.assertIn("`detector_errors.macos_privacy`", macos)
        self.assertNotIn("the scan stays complete", macos)

    def test_fg04a_windows_plugin_refusal_is_structured(self):
        section = page("enterprise/windows.mdx").split("- Claude Code runs a plugin", 1)[1].split("- MCP servers", 1)[0]
        self.assertIn("ASSET-POLICY reason_code=install-block", section)
        self.assertIn("gateway audit log and `defenseclaw plugin info`", section)
        self.assertNotIn("the refusal\n  says `plugin", section)

    def test_fg04a_sandbox_image_action_mode_cross_link(self):
        text = page("sandboxes/guide.mdx")
        self.assertIn("For action mode on a host without the agent installed", text)
        self.assertIn("[connector compatibility guide](/docs/connectors/compatibility)", text)

    def test_lfwin_guardian_first_reconcile_wait(self):
        text = page("enterprise/troubleshooting.mdx")
        self.assertIn("Setup waits up to 10 minutes for the guardian's first reconcile", text)
        self.assertIn("hook_guardian_startup.json", text)
        self.assertIn("no longer running during its first reconcile", text)

    def test_fg12_uninstall_incomplete_code(self):
        row = next(line for line in page("enterprise/troubleshooting.mdx").splitlines()
                   if line.startswith("| `uninstall_incomplete` |"))
        self.assertIn("started the services again", row)

    def test_fg12_linux_package_removal_keeps_files(self):
        text = page("enterprise/linux.mdx")
        self.assertIn("apt or dnf fails and keeps the package files", text)
        self.assertIn("`uninstall_incomplete`", text)

    def test_fg12_doctor_prints_pinned_driver_digest(self):
        section = page("enterprise/sandboxes.mdx").split("### Recipe: prerequisite mode", 1)[1]
        self.assertIn("install command with the SHA-256 digest this DefenseClaw build pins", section)
        self.assertNotIn("and its `.sha256` file", section)

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
