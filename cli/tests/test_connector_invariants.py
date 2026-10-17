# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Shared invariant comparison and Claude bindings; entirely offline."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.connector_delta import invariants as engine  # noqa: E402
from scripts.connector_delta import monitor  # noqa: E402
from scripts.connector_delta.connectors.claudecode.provider import ClaudeProvider  # noqa: E402


class SharedInvariantTests(unittest.TestCase):
    def setUp(self):
        self.provider = ClaudeProvider(ROOT)

    def claim(self, invariant, kind, value, **extra):
        text = "Explicit upstream contract fact."
        revision = hashlib.sha256(text.encode()).hexdigest()
        self.provider.texts[("fixture:upstream", revision)] = text
        ref = engine.evidence(
            text,
            0,
            len(text),
            artifact="fixture:upstream",
            revision=revision,
            role="upstream",
            authority="explicit_statement",
        )
        return {
            "invariant_id": invariant,
            "kind": kind,
            "value": value,
            "authority": "explicit_statement",
            "evidence": [ref],
            **extra,
        }

    def compare(self, invariant, claims, local=None, transport="command-hook"):
        return engine.compare(
            self.provider.catalog[invariant],
            local or self.provider.local()[invariant],
            claims,
            transport=transport,
            texts=self.provider.texts,
        )

    def test_all_current_claude_bindings_are_grounded_in_code(self):
        local = self.provider.local()
        self.assertEqual(set(local), set(self.provider.catalog))
        for invariant, binding in local.items():
            with self.subTest(invariant=invariant):
                self.assertTrue(binding["verified"])
                self.assertTrue(engine.checked_claim(binding, self.provider.texts))
        self.assertEqual(local["hook.discovery"]["values"]["paths"], ["~/.claude/settings.json"])
        self.assertEqual(local["hook.execution"]["values"]["timeouts"]["PreToolUse"], 30)
        self.assertEqual(local["hook.failure"]["values"]["blocking_exit_codes"], [2])
        responses = local["hook.decision"]["values"]["responses"]
        self.assertEqual(responses["PreToolUse"], {"hookSpecificOutput.permissionDecision": "deny"})
        self.assertEqual(responses["UserPromptSubmit"], {"decision": "block"})
        self.assertNotIn("TaskCompleted", responses)  # This event relies on exit status, not JSON.

    def test_vendor_neutral_comparator_accepts_a_different_provider_binding(self):
        text = 'write_config("~/.another-agent/hook-map.json")'
        self.provider.texts[("another/provider.go", "local-revision")] = text
        binding = {
            "verified": True,
            "scope": "user-default",
            "values": {"paths": ["~/.another-agent/hook-map.json"]},
            "evidence": [
                engine.evidence(
                    text,
                    0,
                    len(text),
                    artifact="another/provider.go",
                    revision="local-revision",
                    role="local",
                    authority="local_code",
                )
            ],
        }
        claim = self.claim("hook.discovery", "retired_path", "~/.another-agent/hook-map.json")
        result = self.compare("hook.discovery", [claim], binding)
        self.assertEqual(result["verdict"], "breaking_change")
        self.assertFalse(result["runtime_verified"])

    def test_proxy_transport_is_explicitly_not_applicable(self):
        self.assertEqual(self.compare("hook.discovery", [], transport="proxy")["verdict"], "not_applicable")

    def test_version_before_declared_support_does_not_inherit_latest_compatibility(self):
        self.assertTrue(all(not binding["verified"] for binding in self.provider.local("2.1.150").values()))

    def test_local_extraction_failure_is_unknown_even_when_upstream_looks_compatible(self):
        binding = copy.deepcopy(self.provider.local()["hook.discovery"])
        binding["verified"] = False
        claim = self.claim("hook.discovery", "accepted_paths", ["~/.claude/settings.json"])
        self.assertEqual(self.compare("hook.discovery", [claim], binding)["verdict"], "review_required")

    def test_invented_span_revision_quote_line_or_authority_cannot_prove_a_break(self):
        for key, replacement in (
            ("start", -1),
            ("revision", "wrong"),
            ("quote", "made up"),
            ("line", 500),
            ("role", "local"),
            ("authority", "example"),
        ):
            claim = self.claim("hook.discovery", "retired_path", "~/.claude/settings.json")
            claim["evidence"][0][key] = replacement
            with self.subTest(key=key):
                self.assertEqual(self.compare("hook.discovery", [claim])["verdict"], "review_required")

    def test_malformed_or_wrong_family_facts_are_not_compatible(self):
        for kind, value in (
            ("accepted_paths", {"bad": True}),
            ("exclusive_paths", [[]]),
            ("retired_path", []),
            ("unknown_kind", "x"),
            ("event_removed", None),
        ):
            claim = self.claim("hook.discovery", kind, value, event="PreToolUse")
            with self.subTest(kind=kind):
                self.assertEqual(self.compare("hook.discovery", [claim])["verdict"], "review_required")

    def test_event_omission_is_not_removal(self):
        claim = self.claim("hook.event_delivery", "event_inventory", ["PreToolUse"])
        self.assertEqual(self.compare("hook.event_delivery", [claim])["verdict"], "review_required")

    def test_breaking_claim_wins_over_positive_claim_in_same_delta(self):
        claims = [
            self.claim("hook.discovery", "accepted_paths", ["~/.claude/settings.json"]),
            self.claim("hook.discovery", "retired_path", "~/.claude/settings.json"),
        ]
        self.assertEqual(self.compare("hook.discovery", claims)["verdict"], "breaking_change")

    def test_go_shape_change_invalidates_binding_instead_of_using_stale_manifest_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path, text, _ in self.provider.sources.values():
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8")
            config = root / self.provider.spec["local_sources"]["registration"]
            config.write_text(config.read_text().replace('"settings.json"', '"new-settings.json"'), encoding="utf-8")
            changed = ClaudeProvider(root)
            self.assertFalse(changed.local()["hook.discovery"]["verified"])

    def test_synthetic_mutation_backtest(self):
        result = monitor.invariant_backtest()
        for case in result["cases"]:
            with self.subTest(case=case["id"]):
                self.assertTrue(case["passed"], json.dumps({key: case[key] for key in ("expected", "actual")}))
        self.assertEqual(result["passed"], result["total"])
        self.assertIn("Synthetic", result["evaluation"])

    def test_release_analysis_never_borrows_current_document_evidence(self):
        text = "- Changed PreToolUse hook input."
        source = {"id": "fixture", "url": "fixture:release", "revision": "r1", "text": text, "kind": "changelog"}
        candidate = monitor.make_candidate(source, text, "release_note", line=1, version="2.1.300")
        checks = self.provider.checks(candidate, source, None, ["input_correlation"])
        self.assertTrue(all(row["verdict"] == "review_required" and not row["upstream_claims"] for row in checks))

    def test_duplicate_release_text_cites_the_actual_bullet_line(self):
        text = "## 2.1.301\n\n- Added `FutureEvent` hook event.\n\n## 2.1.300\n\n- Added `FutureEvent` hook event.\n"
        source = {"id": "fixture", "url": "fixture:release", "revision": "r1", "text": text, "kind": "changelog"}
        candidate = monitor.candidates(source)[1]
        check = self.provider.checks(candidate, source, None, [])[0]
        self.assertEqual(check["upstream_claims"][0]["evidence"][0]["line"], 7)

    def test_another_document_hunk_cannot_supply_a_breaking_fact(self):
        before = (
            "# Hooks\n\nOld hook wording.\n" + "\nNeutral context." * 20 + "\nHooks are read from the local config.\n"
        )
        after = before.replace("Old hook wording", "New hook wording").replace(
            "Hooks are read from the local config.", "Hooks are no longer read from `~/.claude/settings.json`."
        )
        source = {"id": "fixture", "url": "fixture:docs", "revision": "r2", "kind": "document", "text": after}
        previous = {**source, "revision": "r1", "text": before}
        changes = monitor.candidates(source, previous)
        self.assertEqual(len(changes), 2)
        first = self.provider.checks(changes[0], source, previous, ["config_discovery"])
        second = self.provider.checks(changes[1], source, previous, ["config_discovery"])
        self.assertTrue(all(row["verdict"] == "review_required" for row in first))
        self.assertTrue(any(row["verdict"] == "breaking_change" for row in second))

    def test_offline_mutation_cli(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(monitor, "request_text", side_effect=AssertionError("network is not allowed")),
        ):
            output = Path(directory) / "report.json"
            code = monitor.main(["backtest-invariants", "--output", str(output)])
            self.assertEqual(code, 0)
            self.assertTrue(output.is_file())


if __name__ == "__main__":
    unittest.main()
