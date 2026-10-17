# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Offline PR inventory and platform-scoping regression tests."""

import copy
import json
import unittest

from cli.tests.test_connector_delta_monitor import snapshot
from scripts.connector_delta import inventory, monitor, platforms


def pr(number=100293, title="Add managed settings example", date="2026-10-09T16:16:37Z"):
    return {
        "number": number,
        "merge_commit_sha": "b" * 40,
        "merged_at": date,
        "updated_at": date,
        "base": {"ref": "main"},
        "title": title,
    }


def fetcher(rows, paths):
    def fetch(url, **kwargs):
        if "/files?" in url:
            return json.dumps([{"filename": path} for path in paths])
        return json.dumps(rows)

    return fetch


class InventoryTests(unittest.TestCase):
    def manifest(self, connector="claudecode"):
        return monitor.load_manifest(monitor.CONFIG / "connectors" / connector / "manifest.json")

    def test_claude_example_outside_watchlist_is_found(self):
        result = inventory.collect(self.manifest(), fetcher([pr()], ["examples/settings/settings-hipaa.json"]))
        self.assertEqual(result["prs"][0]["changed_files"][0]["invariants"], ["hook.discovery", "hook.registration"])

    def test_codex_context_renderer_outside_watchlist_is_found(self):
        result = inventory.collect(
            self.manifest("codex"), fetcher([pr(54776)], ["codex-rs/core/src/context/hook_additional_context.rs"])
        )
        self.assertEqual(len(result["prs"][0]["changed_files"]), 1)

    def test_watched_file_is_not_duplicate_coverage_warning(self):
        result = inventory.collect(self.manifest("codex"), fetcher([pr(54776)], ["codex-rs/hooks/src/schema.rs"]))
        self.assertEqual(result["prs"][0]["changed_files"], [])

    def test_hook_artifact_renamed_to_unrecognized_name_is_still_reviewed(self):
        def fetch(url, **kwargs):
            return json.dumps(
                [
                    {
                        "filename": "codex-rs/core/src/context/context.rs",
                        "previous_filename": "codex-rs/core/src/context/hook_additional_context.rs",
                    }
                ]
                if "/files?" in url
                else [pr(54776)]
            )

        result = inventory.collect(self.manifest("codex"), fetch)
        self.assertTrue(result["prs"][0]["changed_files"])

    def test_irrelevant_file_does_not_become_coverage_warning(self):
        result = inventory.collect(self.manifest(), fetcher([pr()], ["README.md"]))
        self.assertEqual(result["prs"][0]["changed_files"], [])

    def test_unmerged_and_other_base_prs_are_not_analyzed(self):
        rows = [{**pr(), "merged_at": None}, {**pr(2), "base": {"ref": "release"}}]
        self.assertEqual(inventory.collect(self.manifest(), fetcher(rows, []))["prs"], [])

    def test_first_batch_is_latest_ten_later_batch_drains_oldest_first(self):
        rows = [pr(i, date=f"2026-10-{i:02d}T00:00:00Z") for i in range(1, 16)]
        initial = inventory.collect(self.manifest(), fetcher(rows, []))
        self.assertEqual([row["number"] for row in initial["prs"]], list(range(6, 16)))
        later = inventory.collect(
            self.manifest(), fetcher(rows, []), {"pr_inventory": {"watermark": "2026-10-01T00:00:00Z", "seen": []}}
        )
        self.assertEqual([row["number"] for row in later["prs"]], list(range(1, 11)))
        self.assertEqual(later["deferred"], 5)

    def test_bad_commit_identity_is_refused(self):
        with self.assertRaises(ValueError):
            inventory.collect(self.manifest(), fetcher([{**pr(), "merge_commit_sha": "main"}], []))

    def test_file_bound_is_incomplete_not_compatible(self):
        def fetch(url, **kwargs):
            return json.dumps([{"filename": "README.md"}] * 100 if "/files?" in url else [pr()])

        result = inventory.collect(self.manifest(), fetch)
        self.assertTrue(result["errors"])
        self.assertFalse(result["prs"][0]["complete"])

    def test_incremental_notice_even_when_watched_artifacts_do_not_change(self):
        manifest = self.manifest()
        _, state = monitor.run_monitor(snapshot(), manifest)
        current = snapshot()
        current["pr_inventory"] = inventory.collect(
            manifest, fetcher([pr()], ["examples/settings/settings-hipaa.json"])
        )
        report, state = monitor.run_monitor(current, manifest, state)
        self.assertEqual(report["summary"], {"review_required": 1})
        finding = report["findings"][0]
        self.assertEqual(finding["analysis_status"], "unwatched_pr_artifact")
        self.assertTrue(finding["invariants"])
        repeated, _ = monitor.run_monitor(current, manifest, state)
        self.assertFalse(repeated["findings"])

    def test_inventory_error_is_a_coverage_gap(self):
        manifest = self.manifest()
        current = snapshot()
        current["pr_inventory"] = {"repository": "anthropics/claude-code", "prs": [], "errors": ["failed"]}
        report, state = monitor.run_monitor(current, manifest)
        self.assertEqual(report["outcome"], "incomplete")
        self.assertEqual(state["pr_inventory"]["watermark"], "")

    def test_collection_requires_explicit_inventory_opt_in(self):
        calls = []

        def fetch(url, **kwargs):
            calls.append(url)
            if "/commits/main" in url:
                return json.dumps({"sha": "a" * 40})
            return "## 2.1.300\n\n- Test.\n" if "CHANGELOG" in url else "# Docs\n"

        monitor.collect(self.manifest(), fetch)
        self.assertFalse(any("/pulls" in url for url in calls))

    def test_inventory_url_allowlist_is_narrow(self):
        good = "https://api.github.com/repos/openai/codex/pulls?state=closed&base=main&sort=updated&direction=desc&per_page=100&page=1"
        self.assertEqual(monitor.checked_url(good), good)
        for bad in (
            good.replace("openai/codex", "attacker/repo"),
            good.replace("page=1", "page=999"),
            good + "&extra=1",
        ):
            with self.subTest(bad=bad), self.assertRaises(monitor.MonitorError):
                monitor.checked_url(bad)

    def test_os_scope_and_wsl_are_not_host_detection(self):
        for text, expected in (
            ("On Windows", ["windows"]),
            ("macOS", ["macos"]),
            ("WSL2", ["linux"]),
            ("a portable schema", []),
        ):
            self.assertEqual(platforms.scope(text), expected)

    def test_os_specific_path_claim_cannot_become_global_proof(self):
        provider = monitor.PROVIDERS["claudecode"](monitor.ROOT)
        checks = platforms.evaluate(provider, provider.local(), [], ["hook.discovery"], "On Windows the path changed")
        self.assertEqual(checks[0]["verdict"], "review_required")
        self.assertFalse(checks[0]["local_binding_verified"])
        self.assertEqual(checks[0]["platforms"], ["windows"])

    def test_platform_evaluation_does_not_mutate_cached_bindings(self):
        provider = monitor.PROVIDERS["codex"](monitor.ROOT)
        before = copy.deepcopy(provider.local())
        platforms.evaluate(provider, provider.local(), [], ["hook.execution"], "Windows")
        self.assertEqual(provider.local(), before)
        self.assertEqual(set(provider.platform_coverage), {"linux", "macos", "windows"})
        self.assertTrue(all(not item["runtime_verified"] for item in provider.platform_coverage.values()))


if __name__ == "__main__":
    unittest.main()
