# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""OS/deployment isolation, evidence loss and safe rollout regression tests."""

import unittest
from pathlib import Path

from cli.tests.connector_delta.test_monitor import snapshot
from scripts.connector_delta import invariants, monitor, platforms
from scripts.connector_delta.platform_bindings import canonical_path


class PlatformTests(unittest.TestCase):
    def check(self, connector, text, invariant):
        provider = monitor.PROVIDERS[connector](monitor.ROOT)
        revision, artifact = monitor.digest(text), "fixture:scoped-upstream"
        provider.texts[(artifact, revision)] = text
        claims = platforms.extract_scoped(provider, text, artifact, revision)
        return platforms.evaluate(provider, provider.local(), claims, [invariant], text)

    def test_all_supported_file_and_launcher_profiles_are_grounded(self):
        for name, cls in monitor.PROVIDERS.items():
            provider = cls(monitor.ROOT)
            for os, deployments in platforms.profiles(provider, provider.local()).items():
                for deployment, bindings in deployments.items():
                    for key, binding in bindings.items():
                        with self.subTest(connector=name, os=os, deployment=deployment, invariant=key):
                            self.assertTrue(binding["verified"])
                            self.assertTrue(invariants.checked_claim(binding, provider.texts))

    def test_actual_managed_paths_are_distinct_from_user_paths(self):
        for connector, platform, path in (
            ("codex", "linux", "/etc/codex/requirements.toml"),
            ("codex", "macOS", "/etc/codex/requirements.toml"),
            ("codex", "Windows", "%ProgramData%\\OpenAI\\Codex\\requirements.toml"),
            ("claudecode", "Linux", "/etc/claude-code/managed-settings.d/90-defenseclaw.json"),
            ("claudecode", "macOS", "/Library/Application Support/ClaudeCode/managed-settings.d/90-defenseclaw.json"),
            ("claudecode", "Windows", "%ProgramFiles%\\ClaudeCode\\managed-settings.d\\90-defenseclaw.json"),
        ):
            with self.subTest(connector=connector, platform=platform):
                text = f"On {platform.title() if platform == 'linux' else platform}, managed hooks are no longer read from `{path}`."
                checks = self.check(connector, text, "hook.discovery")
                self.assertEqual(checks[0]["verdict"], "breaking_change")
                self.assertEqual(checks[0]["deployment_scope"], "managed")
                self.assertFalse(checks[0]["runtime_verified"])
                user = self.check(connector, text.replace(", managed hooks", ", user hooks"), "hook.discovery")
                self.assertEqual(user[0]["verdict"], "compatible")

    def test_windows_launchers_do_not_leak_into_unix_or_other_modes(self):
        for connector, deployment, launcher, expected in (
            ("claudecode", "user", "cmd.exe", "breaking_change"),
            ("claudecode", "managed", "cmd.exe", "compatible"),
            ("claudecode", "managed", "native-exec", "breaking_change"),
            ("codex", "user", "powershell.exe", "breaking_change"),
            ("codex", "managed", "powershell.exe", "breaking_change"),
            ("codex", "managed", "cmd.exe", "compatible"),
        ):
            text = f"On Windows, {deployment} hooks no longer accept `{launcher}` launchers."
            with self.subTest(connector=connector, deployment=deployment, launcher=launcher):
                self.assertEqual(self.check(connector, text, "hook.execution")[0]["verdict"], expected)
                self.assertEqual(
                    self.check(connector, text.replace("Windows", "Linux"), "hook.execution")[0]["verdict"],
                    "compatible",
                )

    def test_managed_policy_keys_use_the_managed_writer(self):
        for connector, key in (("codex", "windows_managed_dir"), ("claudecode", "allowManagedHooksOnly")):
            text = f"On Windows, managed hooks no longer accept the `{key}` registration key."
            self.assertEqual(self.check(connector, text, "hook.registration")[0]["verdict"], "breaking_change")
            self.assertEqual(
                self.check(connector, text.replace(", managed", ", user"), "hook.registration")[0]["verdict"],
                "compatible",
            )

    def test_document_scope_change_is_not_lost_as_an_unchanged_fact(self):
        manifest = monitor.load_manifest()
        before = "On Linux, user hooks no longer accept `cmd.exe` launchers.\n"
        after = before.replace("Linux", "Windows")
        _, state = monitor.run_monitor(snapshot(hooks=before), manifest)
        report, _ = monitor.run_monitor(snapshot(hooks=after), manifest, state)
        checks = [check for finding in report["findings"] for check in finding["invariants"]]
        affected = [check for check in checks if check["invariant_id"] == "hook.execution"]
        self.assertTrue(any(check["verdict"] == "breaking_change" for check in affected))
        self.assertTrue(all(check["platforms"] == ["windows"] for check in affected))

    def test_legacy_managed_user_codex_is_not_machine_requirements(self):
        text = "On Windows, legacy managed hooks are no longer read from `~/.codex/managed_config.toml`."
        self.assertEqual(self.check("codex", text, "hook.discovery")[0]["verdict"], "breaking_change")
        self.assertEqual(
            self.check("codex", text.replace("legacy managed", "managed"), "hook.discovery")[0]["verdict"], "compatible"
        )

    def test_multiple_os_statements_are_evaluated_separately(self):
        text = "On Windows, user hooks no longer accept `cmd.exe` launchers.\nOn Linux, user hooks no longer accept `cmd.exe` launchers."
        checks = self.check("claudecode", text, "hook.execution")
        results = {tuple(check["platforms"]): check["verdict"] for check in checks}
        self.assertEqual(results, {("windows",): "breaking_change", ("linux",): "compatible"})

    def test_wsl_uses_linux_paths_not_native_windows(self):
        text = "On WSL2, managed hooks are no longer read from `/etc/codex/requirements.toml`."
        row = self.check("codex", text, "hook.discovery")[0]
        self.assertEqual(row["verdict"], "breaking_change")
        self.assertEqual(row["platforms"], ["linux"])

    def test_absolute_windows_install_root_is_not_assumed_from_a_template(self):
        text = "On Windows, managed hooks are no longer read from `C:\\ProgramData\\OpenAI\\Codex\\requirements.toml`."
        # The API-resolved ProgramData root is not necessarily on C:.
        self.assertEqual(self.check("codex", text, "hook.discovery")[0]["verdict"], "review_required")

    def test_examples_conditionals_fixes_and_ambiguous_os_remain_review(self):
        sentence = "On Windows, user hooks no longer accept `cmd.exe` launchers."
        for text in (
            "If " + sentence,
            "Fixed " + sentence,
            "```text\n" + sentence + "\n```",
            "On Windows or Linux, user hooks no longer accept `cmd.exe` launchers.",
            "On Windows hooks changed",
            sentence.replace("user hooks", "project hooks"),
        ):
            with self.subTest(text=text):
                self.assertEqual(self.check("claudecode", text, "hook.execution")[0]["verdict"], "review_required")

    def test_changed_or_commented_local_path_does_not_manufacture_binding(self):
        provider = monitor.PROVIDERS["codex"](monitor.ROOT)
        common = provider.local()
        path, text, sha = provider.sources["machine_paths"]
        for changed in (
            text.replace("return machinePath(opts,", "return anotherResolver(opts,"),
            "/*\n" + text + "\n*/",
        ):
            provider.sources["machine_paths"] = (path, changed, sha)
            profile = provider.platform_bindings(common)["windows"]["managed"]["hook.discovery"]
            self.assertFalse(profile["verified"])

    def test_canonical_paths_are_symbolic_and_os_scoped(self):
        self.assertEqual(canonical_path("%USERPROFILE%\\.codex\\CONFIG.TOML", "windows"), "~/.codex/config.toml")
        self.assertNotEqual(canonical_path("/Etc/Codex", "linux"), canonical_path("/etc/codex", "linux"))

    def test_coverage_does_not_certify_live_clients(self):
        for cls in monitor.PROVIDERS.values():
            for row in platforms.coverage(cls(monitor.ROOT)).values():
                self.assertFalse(row["runtime_verified"])
                self.assertEqual(row["status"], "partial_static_coverage")

    def test_checked_claim_offsets_cannot_be_forged_for_scoped_comparison(self):
        provider = monitor.PROVIDERS["claudecode"](monitor.ROOT)
        text = "On Windows, user hooks no longer accept `cmd.exe` launchers."
        provider.texts[("fixture", "revision")] = text
        claims = platforms.extract_scoped(provider, text, "fixture", "revision")
        claims[0]["evidence"][0]["quote"] = "invented"
        rows = platforms.evaluate(provider, provider.local(), claims, ["hook.execution"], text)
        self.assertEqual(rows[0]["verdict"], "review_required")

    def test_workflow_smoke_and_production_publishing_are_separate(self):
        root = Path(__file__).resolve().parents[3]
        checks = (root / ".github/workflows/connector-delta-checks.yml").read_text()
        production = (root / ".github/workflows/connector-delta-monitor.yml").read_text()
        self.assertIn("[ubuntu-latest, macos-latest, windows-latest]", checks)
        self.assertIn("--repo monitor-main", checks)
        self.assertIn("CONNECTOR_DELTA_NOTIFICATIONS_ENABLED: 'false'", checks)
        self.assertIn("--ai off", checks)
        self.assertNotIn("issues: write", checks)
        self.assertNotIn("secrets.", checks)
        self.assertIn("inputs.notify == true", production)
        self.assertIn("default: false", production)
        self.assertIn("github.ref == 'refs/heads/main'", production)


if __name__ == "__main__":
    unittest.main()
