# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Codex provider, source collection, replay and evidence boundaries; no network."""

from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.connector_delta import monitor  # noqa: E402
from scripts.connector_delta.connectors.codex.provider import CodexProvider, json_span, schema_property  # noqa: E402
from scripts.connector_delta.history import collect_history, replay_history  # noqa: E402
from scripts.connector_delta.invariants import InvariantError  # noqa: E402

SHA, PARENT = "b" * 40, "a" * 40


def source_snapshot(manifest, changed=None, revision=PARENT):
    changed = changed or {}
    sources = []
    for spec in manifest["sources"]:
        text = monitor.normalize(changed.get(spec["id"], "{}" if spec["path"].endswith(".json") else "// baseline\n"))
        sources.append(
            {
                "id": spec["id"],
                "url": spec["url"].format(revision=revision),
                "revision": revision,
                "kind": "source",
                "text": text,
                "content_sha256": monitor.digest(text),
            }
        )
    return {"schema_version": 1, "connector": "codex", "sources": sources, "errors": []}


def deny_schema(allowed):
    return json.dumps(
        {
            "title": "pre-tool-use.command.output",
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "hookSpecificOutput": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {"permissionDecision": {"type": "string", "enum": allowed}},
                }
            },
        },
        indent=2,
    )


class CodexDeltaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = monitor.load_manifest(monitor.CONFIG / "connectors/codex/manifest.json")

    def test_real_local_bindings_do_not_use_claude_paths_or_historical_timeout(self):
        provider = CodexProvider(ROOT)
        local = provider.local()
        self.assertTrue(all(binding["verified"] for binding in local.values()))
        self.assertEqual(local["hook.discovery"]["values"]["paths"], ["~/.codex/config.toml"])
        self.assertEqual(local["hook.execution"]["values"]["timeouts"]["SessionEnd"], 3)
        self.assertEqual(local["hook.execution"]["values"]["timeouts"]["PreToolUse"], 30)
        self.assertEqual(local["hook.decision"]["values"]["responses"]["SessionStart"], {"continue": False})
        self.assertNotIn("SessionEnd", local["hook.decision"]["values"]["responses"])
        self.assertEqual(len(provider.local("0.124.0")["hook.event_delivery"]["values"]["events"]), 6)
        self.assertFalse(provider.local("0.123.0")["hook.discovery"]["verified"])

    def test_all_codex_mutations(self):
        report = monitor.invariant_backtest(connector="codex")
        for case in report["cases"]:
            with self.subTest(case=case["id"]):
                self.assertTrue(case["passed"], str(case["actual"]))
        self.assertEqual(report["passed"], report["total"])

    def test_current_sources_seed_then_detect_exact_deny_enum_retirement_without_ai(self):
        before = source_snapshot(self.manifest, {"codex-pre-tool-use-output": deny_schema(["allow", "deny"])})
        after = source_snapshot(self.manifest, {"codex-pre-tool-use-output": deny_schema(["allow"])}, SHA)
        first, state = monitor.run_monitor(before, self.manifest)
        self.assertEqual(first["findings"], [])
        self.assertTrue(all(row["status"] == "baseline_created" for row in first["sources"]))
        second, _ = monitor.run_monitor(after, self.manifest, state)
        self.assertEqual(second["findings"][0]["decision"], "breaking_change")
        self.assertEqual(second["findings"][0]["invariants"][0]["invariant_id"], "hook.decision")
        self.assertEqual(second["connector"], "codex")
        self.assertEqual(second["ai_calls"], 0)
        self.assertIn("codex", monitor.markdown(second))

    def test_source_fingerprints_and_connector_boundaries(self):
        value = source_snapshot(self.manifest)
        value["sources"][0]["text"] += "tampered"
        with self.assertRaisesRegex(monitor.MonitorError, "hash mismatch"):
            monitor.run_monitor(value, self.manifest)
        value = source_snapshot(self.manifest)
        value["connector"] = "claudecode"
        with self.assertRaisesRegex(monitor.MonitorError, "different connector"):
            monitor.run_monitor(value, self.manifest)

    def test_collection_pins_every_source_to_one_commit_and_scopes_auth(self):
        calls = []

        def fetch(url, **options):
            calls.append((url, options))
            return json.dumps({"sha": SHA}) if "api.github.com" in url else "// Official source\n"

        with patch.dict(os.environ, {"GH_TOKEN": "unit-test-placeholder"}):
            result = monitor.collect(self.manifest, fetch)
        self.assertFalse(result["errors"])
        self.assertEqual(len(calls), len(self.manifest["sources"]) + 1)
        self.assertEqual({row["revision"] for row in result["sources"]}, {SHA})
        self.assertTrue(all("headers" not in options for _, options in calls[1:]))

    def test_codex_allowlist_rejects_arbitrary_paths_refs_and_history_queries(self):
        for url in (
            f"https://raw.githubusercontent.com/openai/codex/{SHA}/README.md",
            "https://raw.githubusercontent.com/openai/codex/main/codex-rs/hooks/src/schema.rs",
            "https://api.github.com/repos/openai/codex/commits?sha=evil&path=codex-rs/hooks&per_page=15",
            "https://api.github.com/repos/openai/codex/commits?sha=main&path=arbitrary&per_page=15",
            "https://api.github.com/repos/openai/codex/commits?sha=main&path=codex-rs/hooks&per_page=999",
        ):
            with self.subTest(url=url), self.assertRaises(monitor.MonitorError):
                monitor.checked_url(url)

    def test_local_schema_refs_resolve_exact_spans_but_never_remote_or_cycles(self):
        provider = CodexProvider(ROOT)
        for unknown in ("true", "[]", '{"title":42}'):
            self.assertEqual(
                provider.extract(
                    {
                        "id": "codex-pre-tool-use-output",
                        "url": "fixture:pre-tool-use.command.output.schema.json",
                        "revision": SHA,
                        "text": unknown,
                    }
                ),
                [],
            )
        doc = {
            "properties": {"x": {"allOf": [{"$ref": "#/definitions/Choice"}]}},
            "definitions": {"Choice": {"enum": ["allow", "deny"], "type": "string"}},
        }
        text = json.dumps(doc, indent=2)
        node, pointer = schema_property(text, ["x"])
        self.assertEqual(node["enum"], ["allow", "deny"])
        value, start, end = json_span(text, pointer)
        self.assertEqual(json.loads(text[start:end]), value)
        doc["definitions"]["Choice"] = {"$ref": "#/definitions/Choice"}
        self.assertIsNone(schema_property(json.dumps(doc), ["x"])[0])
        doc["properties"]["x"] = {"$ref": "https://invalid.example/private"}
        self.assertIsNone(schema_property(json.dumps(doc), ["x"])[0])
        with self.assertRaises(InvariantError):
            json_span('{"x":1,"x":2}', ["x"])

    def test_comments_cannot_manufacture_a_timeout_conflict(self):
        provider = CodexProvider(ROOT)
        text = "// pub(crate) const SESSION_END_MAX_TIMEOUT_SEC: u64 = 1;\n"
        source = {"id": "codex-session-end", "url": "fixture:session_end.rs", "revision": SHA, "text": text}
        self.assertEqual(provider.extract(source), [])

    def test_nested_rust_comments_cannot_supply_contract_facts(self):
        provider = CodexProvider(ROOT)
        source = {
            "id": "codex-session-end",
            "url": "fixture:session_end.rs",
            "revision": SHA,
            "text": "/* outer /* inner */\npub(crate) const SESSION_END_MAX_TIMEOUT_SEC: u64 = 1;\n*/\n",
        }
        self.assertEqual(provider.extract(source), [])
        source["text"] = 'let text = r#"pub(crate) const SESSION_END_MAX_TIMEOUT_SEC: u64 = 1;"#;\n'
        self.assertEqual(provider.extract(source), [])

    def test_codex_prompt_uses_its_own_binding_ranges(self):
        candidate = {"text": "@@ -1 +1 @@\n-old\n+new", "source": "codex-pre-tool-use-output", "kind": "document_diff"}
        matches = monitor.match_rules(candidate, self.manifest)
        packet = monitor.local_context(candidate, matches, ROOT, connector="codex")
        self.assertEqual(packet["connector"], "codex")
        paths = {ref["path"] for inv in packet["invariants"] for ref in inv["local_evidence_ranges"]}
        self.assertIn("internal/gateway/connector/codex_hook_profile.go", paths)
        self.assertFalse(any("claudecode" in path for path in paths))

    def test_codex_optional_ai_adapter_receives_only_its_scoped_evidence(self):
        before = source_snapshot(self.manifest, {"codex-output-parser": "fn parse_output() { old_behavior(); }\n"})
        after = source_snapshot(self.manifest, {"codex-output-parser": "fn parse_output() { new_behavior(); }\n"}, SHA)
        _, state = monitor.run_monitor(before, self.manifest, ai="anthropic", model="fixture")
        packets = []

        def analyzer(packet, model, system):
            packets.append(packet)
            comparisons = []
            for invariant in packet["invariants"]:
                artifact, line = next(
                    (artifact, line)
                    for artifact in packet["local_artifacts"]
                    for line in artifact["lines"]
                    if line["text"].strip()
                    and any(
                        ref["path"] == artifact["path"] and ref["start_line"] <= line["number"] <= ref["end_line"]
                        for ref in invariant["local_evidence_ranges"]
                    )
                )
                comparisons.append(
                    {
                        "invariant_id": invariant["invariant_id"],
                        "upstream_quote": packet["upstream"]["text"],
                        "local_artifact": artifact["path"],
                        "local_line": line["number"],
                        "local_quote": line["text"],
                        "assessment": "Source implementation changed; the response consequence needs review.",
                    }
                )
            return {
                "invariant_ids": [row["invariant_id"] for row in packet["invariants"]],
                "decision": "review_required",
                "impact": "unknown",
                "change_kind": "unknown",
                "summary": "No deterministic contract proof was extracted.",
                "comparisons": comparisons,
                "recommended_tests": [],
                "unknowns": ["No client was run."],
            }

        report, _ = monitor.run_monitor(after, self.manifest, state, ai="anthropic", model="fixture", analyzer=analyzer)
        self.assertEqual(report["ai_calls"], 1)
        self.assertEqual(report["outcome"], "complete")
        self.assertEqual(packets[0]["connector"], "codex")
        self.assertEqual([row["invariant_id"] for row in packets[0]["invariants"]], ["hook.decision"])

    def test_advisory_session_end_timeout_does_not_request_failure_analysis(self):
        provider = CodexProvider(ROOT)
        before = {
            "id": "codex-session-end",
            "url": "fixture:session_end.rs",
            "revision": PARENT,
            "text": "pub(crate) const SESSION_END_DEFAULT_TIMEOUT_SEC: u64 = 1;\n",
        }
        after = {**before, "revision": SHA, "text": "pub(crate) const SESSION_END_DEFAULT_TIMEOUT_SEC: u64 = 2;\n"}
        candidate = monitor.candidates({**after, "kind": "document"}, {**before, "kind": "document"})[0]
        checks = provider.checks(candidate, after, before, ["runtime_behavior"])
        self.assertEqual([row["invariant_id"] for row in checks], ["hook.execution"])

    def test_history_collection_is_bounded_and_uses_pinned_first_parents(self):
        def fetch(url, **options):
            monitor.checked_url(url)
            return json.dumps(
                [
                    {
                        "sha": SHA,
                        "parents": [{"sha": PARENT}],
                        "commit": {"committer": {"date": "2026-10-16T00:00:00Z"}, "message": "Hook change (#1)"},
                    }
                ]
            )

        def collector(manifest, fetch, revision):
            return source_snapshot(manifest, revision=revision)

        report = collect_history(self.manifest, fetch, collector, count=1)
        self.assertEqual(len(report["cases"]), 1)
        self.assertEqual(set(report["snapshots"]), {SHA, PARENT})

    def test_offline_history_replay_retains_missing_parent_coverage(self):
        before = source_snapshot(self.manifest, {"codex-pre-tool-use-output": deny_schema(["allow", "deny"])})
        after = source_snapshot(self.manifest, {"codex-pre-tool-use-output": deny_schema(["allow"])}, SHA)
        history = {
            "schema_version": 1,
            "connector": "codex",
            "scope": "fixture parent-to-commit",
            "cases": [{"commit": SHA, "parent": PARENT, "date": "fixture", "subject": "fixture"}],
            "snapshots": {PARENT: before, SHA: after},
        }
        with patch.object(monitor, "request_text", side_effect=AssertionError("replay must be offline")):
            report = replay_history(history, self.manifest, monitor.run_monitor, root=ROOT)
        self.assertEqual(report["summary"], {"breaking_change": 1})
        self.assertFalse(report["gaps"])
        broken = copy.deepcopy(history)
        broken["snapshots"][PARENT]["sources"].pop()
        report = replay_history(broken, self.manifest, monitor.run_monitor, root=ROOT)
        self.assertEqual(report["outcome"], "incomplete")
        self.assertTrue(any("parent snapshot" in gap["reason"] for gap in report["gaps"]))

    def test_cli_codex_mutations_and_history_need_no_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            with patch.object(monitor, "request_text", side_effect=AssertionError("unexpected network")):
                code = monitor.main(["backtest-invariants", "--connector", "codex", "--output", str(path)])
            self.assertEqual(code, 0)
            result = monitor.load_json(path)
            self.assertEqual(result["passed"], result["total"])

    def test_malformed_history_and_mislabelled_snapshot_are_rejected(self):
        with self.assertRaises(InvariantError):
            collect_history(self.manifest, lambda *args, **kwargs: "[42]", lambda *args: None, count=1)
        history = {
            "schema_version": 1,
            "connector": "codex",
            "scope": "fixture",
            "cases": [{"commit": SHA, "parent": PARENT}],
            "snapshots": {SHA: source_snapshot(self.manifest, revision=PARENT), PARENT: source_snapshot(self.manifest)},
        }
        with self.assertRaisesRegex(InvariantError, "transition revision"):
            replay_history(history, self.manifest, monitor.run_monitor, root=ROOT)


if __name__ == "__main__":
    unittest.main()
