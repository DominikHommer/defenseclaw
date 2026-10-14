"""Regression checks for rel-1-0-2 docs hand-offs and GAP-0554."""

import unittest
from pathlib import Path


DOCS = Path(__file__).resolve().parents[1] / "content/docs"


def page(name):
    return " ".join((DOCS / name).read_text().split())


class R102DocsFinalDocsTest(unittest.TestCase):
    def test_gap_0012_windows_profile_scan_limit(self):
        text = page("enterprise/windows.mdx")
        self.assertIn("health.watcher.details.profile_roots_skipped: true", text)
        self.assertIn("enterprise `status` and `verify` results do not report that field separately", text)
        self.assertIn("A brokered scan as the enrolled user is planned for a later release", text)
        self.assertNotIn("gateway service watches the skill and plugin folders of every user", text)

    def test_gap_0012_admission_profile_roots(self):
        text = page("policies/admission.mdx")
        self.assertIn("assets there do not receive its install-admission scan", text)
        self.assertIn("keep shared skills outside profiles", text)
        self.assertNotIn("on a managed computer only projects inside the user's home count", text)

    def test_gap_0012_skill_watcher_profile_roots(self):
        text = page("scanning/skill-scanner.mdx")
        self.assertIn("skills there receive no watcher scan", text)
        self.assertIn("scan a copy outside profiles", text)

    def test_gap_0012_mcp_watcher_profile_roots(self):
        text = page("scanning/mcp-scanner.mdx")
        self.assertIn("those servers receive no install-watcher scan", text)
        self.assertIn("watcher.details.profile_roots_skipped: true", text)

    def test_gap_0461_kiro_prompt_scope(self):
        text = page("connectors/capability-matrix.mdx")
        self.assertIn("Kiro blocks a matching prompt only in Kiro IDE; `kiro-cli` sends it to the model.", text)
        self.assertNotIn("and Kiro have a prompt hook that can block", text)

    def test_gap_0440_windows_guardian_restore_restart(self):
        text = page("enterprise/windows.mdx")
        self.assertIn("the hook guardian restored hooks that the user changed or removed", text)
        self.assertIn("`security_complete` stays `false` until that session restarts", text)
        self.assertIn("Claude Code, Codex and Cursor use machine policy hooks", text)

    def test_gap_0499_unix_guardian_restore_restart(self):
        text = page("enterprise/troubleshooting.mdx")
        row = text.split("| `agent_sessions_restart_required` |", 1)[1].split("| Ask the user named", 1)[0]
        self.assertIn("hook guardian put back hooks the user changed or removed", row)
        self.assertIn("On Linux and macOS this restore case excludes Codex", row)
        self.assertIn("`security_complete` stays `false` until it restarts", row)
        self.assertNotIn("It names only sessions older than the activation", row)

    def test_gap_0483_rollback_carries_sandbox_setup(self):
        text = page("get-started/upgrade.mdx")
        self.assertIn("Between releases from 1.0.1 on, rollback carries the sandbox setup", text)
        self.assertIn("each sandbox record and hook binding, harness image records, and undo point", text)
        self.assertIn("A release before 1.0.1 cannot take over that setup", text)

    def test_gap_0554_enterprise_sandbox_docker_limit(self):
        text = page("enterprise/sandboxes.mdx")
        bullet = text.split("**Docker is root-equivalent.**", 1)[1].split("- **A registration", 1)[0]
        self.assertIn("container outside DefenseClaw, bypassing `sandbox.required_for` too", bullet)
        self.assertIn("must not give them Docker access", bullet)
        self.assertIn("A root-owned image and lifecycle service", bullet)

    def test_gap_0554_enterprise_linux_docker_limit(self):
        text = page("enterprise/linux.mdx")
        self.assertIn("outside DefenseClaw, bypassing `sandbox.required_for`", text)
        self.assertIn("must not give them Docker access", text)
        self.assertIn("root-owned image and lifecycle service", text)

    def test_gap_0445_cli_unreadable_sandbox_list(self):
        text = page("reference/cli.mdx")
        self.assertIn("`uninstall` and `reset` also stop before any change if DefenseClaw cannot read the sandbox list", text)
        self.assertIn("`error`, `stopping`, `creating` and `deleting` phases count as running", text)
        self.assertIn("Only `stopped`, `completed`, `deleted` and `missing` do not", text)

    def test_gap_0445_guide_unreadable_sandbox_list(self):
        text = page("sandboxes/guide.mdx")
        self.assertIn("`uninstall` and `reset` stop before any change: teardown could otherwise delete a sandbox that still runs", text)
        self.assertIn("Check with `defenseclaw sandbox list`", text)
        self.assertIn("A sandbox in `error`, `stopping`, `creating` or `deleting` counts as running", text)

    def test_gap_0445_install_unreadable_sandbox_list(self):
        text = page("get-started/install.mdx")
        self.assertIn("If the sandbox list cannot be read, `uninstall` and `reset` also stop before any change", text)
        self.assertIn("`error`, `stopping`, `creating` and `deleting` phases count as running", text)

    def test_gap_0226_windows_install_discovery(self):
        text = page("enterprise/enrollment.mdx")
        self.assertIn("official Codex `install.ps1` layout", text)
        self.assertIn("per-user WinGet packages for signed-in users", text)
        self.assertIn("A signed-out user's per-user WinGet package is read at the next sign-in", text)
        self.assertIn("enabled agent running for an account with no enrollment target", text)
        self.assertIn("`security_complete` stays `false`", text)
        self.assertNotIn("is not found, so it is neither enrolled nor reported", text)

    def test_gap_0226_managed_codex_install_locations(self):
        text = page("connectors/codex.mdx")
        self.assertIn("On managed Windows, the enumerator enrolls Codex installed with npm", text)
        self.assertIn("official `install.ps1` at its default location, or WinGet", text)
        self.assertIn("under a relocated `CODEX_HOME`", text)

    def test_gap_0255_profile_explain_account_ids(self):
        text = page("guardrail/user-and-group-policies.mdx")
        self.assertIn("Group assignments follow the OS-verified account ID", text)
        self.assertIn("use each uid or SID with `guardrail profile explain --user`", text)

    def test_gap_0438_guardian_hook_binary_reread(self):
        text = page("enterprise/troubleshooting.mdx")
        self.assertIn("The guardian re-reads the hook binary when it changes and at least every 10 minutes", text)

    def test_gap_0085_grafana_history_and_current_state(self):
        text = page("observability/grafana-dashboards.mdx")
        self.assertIn("The **DefenseClaw kernel policies** table counts policy-change events", text)
        self.assertIn("The stat and **Kernel controls per host (last 10 minutes)** show current host state", text)

if __name__ == "__main__":
    unittest.main()
