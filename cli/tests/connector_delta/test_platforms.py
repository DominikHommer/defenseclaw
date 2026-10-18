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
    def claim(self, provider, text, invariant, kind, value, *, quote=None, **extra):
        artifact, revision = "fixture:claim-source", monitor.digest(text)
        provider.texts[(artifact, revision)] = text
        quote = text if quote is None else quote
        start = text.index(quote)
        return {
            "invariant_id": invariant,
            "kind": kind,
            "value": value,
            "authority": "explicit_statement",
            "evidence": [
                invariants.evidence(
                    text,
                    start,
                    start + len(quote),
                    artifact=artifact,
                    revision=revision,
                    role="upstream",
                    authority="explicit_statement",
                )
            ],
            **extra,
        }

    def check(self, connector, text, invariant):
        provider = monitor.PROVIDERS[connector](monitor.ROOT)
        revision, artifact = monitor.digest(text), "fixture:scoped-upstream"
        provider.texts[(artifact, revision)] = text
        claims = platforms.extract_scoped(provider, text, artifact, revision)
        return platforms.evaluate(provider, provider.local(), claims, [invariant], text)

    def test_lowercase_window_nouns_are_not_windows_os_scope(self):
        for text in ("context windows", "terminal windows", "multiple windows are open"):
            with self.subTest(text=text):
                self.assertEqual(platforms.scope(text), [])
        self.assertEqual(platforms.scope("Linux supports multiple terminal windows."), ["linux"])

    def test_recognized_os_spellings_remain_scoped(self):
        for platform, variants in (
            ("windows", ("Windows", "WINDOWS", "windows", "Win32", "win32", "PowerShell", "powershell")),
            ("linux", ("Linux", "linux", "WSL", "WSL1", "WSL2", "wsl2")),
            ("macos", ("macOS", "macos", "Darwin", "darwin", "Mac OS", "mac os")),
        ):
            for variant in variants:
                with self.subTest(variant=variant):
                    self.assertEqual(platforms.scope(f"On {variant}, hooks changed."), [platform])

    def test_window_nouns_do_not_hide_a_global_path_retirement(self):
        provider = monitor.PROVIDERS["claudecode"](monitor.ROOT)
        for noun in ("context windows", "terminal windows"):
            text = f"Hooks are no longer read from `~/.claude/settings.json`. Larger {noun} are supported."
            claims = provider.extract(text, "fixture:nouns", monitor.digest(text))
            rows = platforms.evaluate(provider, provider.local(), claims, ["hook.discovery"], text)
            with self.subTest(noun=noun):
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["verdict"], "breaking_change")
                self.assertEqual(rows[0]["platforms"], ["unspecified"])

    def test_global_path_and_windows_managed_path_are_both_evaluated(self):
        statements = (
            "Hooks are no longer read from `~/.claude/settings.json`.",
            "On Windows, managed hooks are no longer read from `~/.claude/settings.json`.",
        )
        for lines in (statements, statements[::-1]):
            provider = monitor.PROVIDERS["claudecode"](monitor.ROOT)
            text = "\n".join(lines)
            claims = provider.extract(text, "fixture:mixed", monitor.digest(text))
            rows = platforms.evaluate(provider, provider.local(), claims, ["hook.discovery"], text)
            with self.subTest(lines=lines):
                self.assertEqual(len(rows), 2)
                global_row = next(row for row in rows if row["platforms"] == ["unspecified"])
                scoped_row = next(row for row in rows if row["platforms"] == ["windows"])
                self.assertEqual(global_row["verdict"], "breaking_change")
                self.assertNotIn("deployment_scope", global_row)
                self.assertEqual(scoped_row["verdict"], "compatible")
                self.assertEqual(scoped_row["deployment_scope"], "managed")
                self.assertEqual(len(global_row["upstream_claims"]), 1)
                self.assertEqual(len(scoped_row["upstream_claims"]), 1)
                self.assertEqual(
                    global_row["upstream_claims"][0]["evidence"][0]["line"], lines.index(statements[0]) + 1
                )
        manifest = monitor.load_manifest()
        _, state = monitor.run_monitor(snapshot(hooks="# Hooks\n\nOld discovery documentation.\n"), manifest)
        report, _ = monitor.run_monitor(snapshot(hooks="# Hooks\n\n" + "\n".join(statements) + "\n"), manifest, state)
        finding = next(finding for finding in report["findings"] if finding["decision"] == "breaking_change")
        rows = [row for row in finding["invariants"] if row["invariant_id"] == "hook.discovery"]
        self.assertEqual(
            {(tuple(row["platforms"]), row["verdict"]) for row in rows},
            {
                (("unspecified",), "breaking_change"),
                (("windows",), "compatible"),
            },
        )

    def test_mixed_claims_for_multiple_invariants_providers_and_platforms(self):
        for connector, cls in monitor.PROVIDERS.items():
            provider = cls(monitor.ROOT)
            bindings = provider.local()
            for os in ("Windows", "Linux", "macOS", "WSL2"):
                for invariant, kind, value, statement, scoped_statement, extra in (
                    (
                        "hook.discovery",
                        "retired_path",
                        bindings["hook.discovery"]["values"]["paths"][0],
                        f"Hooks are no longer read from `{bindings['hook.discovery']['values']['paths'][0]}`.",
                        "hooks are no longer read from `~/.unrelated/hooks.json`.",
                        {},
                    ),
                    (
                        "hook.registration",
                        "retired_registration_key",
                        "hooks",
                        "The `hooks` registration key is no longer accepted.",
                        "hooks no longer accept the `unrelated` registration key.",
                        {},
                    ),
                    (
                        "hook.execution",
                        "synchronous",
                        False,
                        "`PreToolUse` hooks run asynchronously.",
                        "hooks no longer accept `unrelated.exe` launchers.",
                        {"event": "PreToolUse"},
                    ),
                ):
                    text = statement + f"\nOn {os}, managed " + scoped_statement
                    claim = self.claim(provider, text, invariant, kind, value, quote=statement, **extra)
                    scoped = platforms.extract_scoped(provider, text, "fixture:claim-source", monitor.digest(text))
                    rows = platforms.evaluate(provider, bindings, [claim, *scoped], [invariant], text)
                    with self.subTest(connector=connector, os=os, invariant=invariant):
                        self.assertEqual(len(rows), 2)
                        self.assertEqual(rows[0]["verdict"], "breaking_change")
                        self.assertEqual(rows[0]["platforms"], ["unspecified"])
                        self.assertEqual(rows[1]["verdict"], "compatible")
                        self.assertEqual(rows[1]["platforms"], platforms.scope(os))
                        self.assertEqual(rows[1]["deployment_scope"], "managed")

    def test_unrelated_os_prose_does_not_scope_a_claim_from_its_source(self):
        provider = monitor.PROVIDERS["claudecode"](monitor.ROOT)
        statement = "Hooks are no longer read from `~/.claude/settings.json`."
        for text in (
            statement + "\nWindows terminal rendering changed.",
            "Windows terminal rendering changed.\n" + statement,
        ):
            start = text.index(statement)
            claims = provider.extract(statement, "fixture:source", monitor.digest(text), base=start, full_text=text)
            rows = platforms.evaluate(provider, provider.local(), claims, ["hook.discovery"], "Windows diff context")
            with self.subTest(text=text):
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["verdict"], "breaking_change")
                self.assertEqual(rows[0]["platforms"], ["unspecified"])

    def test_unscoped_os_conditionals_do_not_borrow_global_or_scoped_proof(self):
        provider = monitor.PROVIDERS["claudecode"](monitor.ROOT)
        global_statement = "Hooks are no longer read from `~/.claude/settings.json`."
        conditional = "Hooks are no longer read from `~/.unrelated/settings.json`"
        for os in ("Windows", "Linux", "macOS", "WSL2", "PowerShell"):
            for line in (f"If running on {os}, {conditional}.", f"{conditional} if running on {os}."):
                text = global_statement + "\n" + line
                claims = [
                    self.claim(provider, text, "hook.discovery", "retired_path", path, quote=quote)
                    for path, quote in (
                        ("~/.claude/settings.json", global_statement),
                        ("~/.unrelated/settings.json", conditional),
                    )
                ]
                for selected_claims in (claims[1:], claims):
                    rows = platforms.evaluate(provider, provider.local(), selected_claims, ["hook.discovery"], text)
                    with self.subTest(os=os, line=line, mixed=len(selected_claims) == 2):
                        self.assertEqual(len(rows), len(selected_claims))
                        self.assertEqual(rows[-1]["verdict"], "review_required")
                        self.assertEqual(rows[-1]["platforms"], platforms.scope(os))
                        self.assertFalse(rows[-1]["local_binding_verified"])
                        self.assertNotIn("deployment_scope", rows[-1])
                        if len(selected_claims) == 2:
                            self.assertEqual(rows[0]["verdict"], "breaking_change")
                            self.assertEqual(rows[0]["platforms"], ["unspecified"])

    def test_mixed_claims_keep_missing_invariants_and_invalid_evidence_in_review(self):
        provider = monitor.PROVIDERS["claudecode"](monitor.ROOT)
        statement = "Hooks are no longer read from `~/.claude/settings.json`."
        text = statement + "\nOn Windows, managed hooks no longer accept `unrelated.exe` launchers."
        claims = provider.extract(text, "fixture:unknown", monitor.digest(text))
        rows = platforms.evaluate(
            provider, provider.local(), claims, ["hook.discovery", "hook.registration", "hook.execution"], text
        )
        self.assertEqual([row["verdict"] for row in rows], ["breaking_change", "review_required", "compatible"])
        for evidence in ([], [{"artifact": "missing", "revision": "missing"}]):
            bad = self.claim(
                provider, text, "hook.execution", "synchronous", False, quote=statement, event="PreToolUse"
            )
            bad["evidence"] = evidence
            rows = platforms.evaluate(provider, provider.local(), [bad, claims[0]], ["hook.execution"], text)
            self.assertEqual([row["verdict"] for row in rows], ["review_required", "compatible"])

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
