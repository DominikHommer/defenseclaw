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

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from scripts.connector_delta import monitor  # noqa: E402
from scripts.connector_delta.connectors.codex.provider import (  # noqa: E402
    CodexProvider,
    json_span,
    rust_test_spans,
    schema_added_fields,
    schema_document,
    schema_property,
    session_routes,
    source_matcher_map,
)
from scripts.connector_delta.connectors.codex.provider import (
    test_only_hunk as is_test_only_hunk,
)
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


def input_schema(**extra_fields):
    return json.dumps(
        {
            "title": "pre-tool-use.command.input",
            "type": "object",
            "additionalProperties": False,
            "properties": {"tool_use_id": {"type": "string"}, "hook_event_name": {"type": "string"}, **extra_fields},
            "required": ["tool_use_id", "hook_event_name"],
        },
        indent=2,
    )


class CodexDeltaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = monitor.load_manifest(monitor.CONFIG / "connectors/codex/manifest.json")

    def test_real_fork_source_transition_identifies_lost_matcher_coverage(self):
        # Source fragments from openai/codex #44349 (e444aa99d76b), not
        # a claim that a live Codex client was executed by this test.
        before_code = """let session_start_source = match &initial_history {
    InitialHistory::Resumed(_) => codex_hooks::SessionStartSource::Resume,
    InitialHistory::New | InitialHistory::Forked(_) => {
        codex_hooks::SessionStartSource::Startup
    }
    InitialHistory::Cleared => codex_hooks::SessionStartSource::Clear,
};"""
        after_code = """let session_start_source = match &initial_history {
    InitialHistory::Forked(_) if forked_from_id.is_some() => {
        codex_hooks::SessionStartSource::Fork
    }
    InitialHistory::Resumed(_) | InitialHistory::Forked(_) => {
        codex_hooks::SessionStartSource::Resume
    }
    InitialHistory::New => codex_hooks::SessionStartSource::Startup,
    InitialHistory::Cleared => codex_hooks::SessionStartSource::Clear,
};"""
        mapping = """impl SessionStartSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Resume => "resume",
            Self::Clear => "clear",
            Self::Fork => "fork",
        }
    }
}
impl StartHookTarget {
    fn matcher_input(&self) -> &str {
        match self {
            Self::SessionStart { source } => source.as_str(),
            Self::SubagentStart { agent_type, .. } => agent_type.as_str(),
        }
    }
}"""
        before = source_snapshot(self.manifest, {"codex-session-init": before_code, "codex-session-start": mapping})
        after = source_snapshot(self.manifest, {"codex-session-init": after_code, "codex-session-start": mapping}, SHA)
        _, state = monitor.run_monitor(before, self.manifest)
        report, _ = monitor.run_monitor(after, self.manifest, state)
        conflicts = [f for f in report["findings"] if f["decision"] == "breaking_change"]
        self.assertTrue(conflicts)
        check = next(c for f in conflicts for c in f["invariants"] if c["verdict"] == "breaking_change")
        self.assertEqual(check["invariant_id"], "hook.event_delivery")
        self.assertIn("fork", check["reason"])
        self.assertFalse(check["runtime_verified"])
        self.assertEqual(report["ai_calls"], 0)
        for mismatch in ("missing", "different_revision"):
            mixed = copy.deepcopy(after)
            if mismatch == "missing":
                mixed["sources"] = [s for s in mixed["sources"] if s["id"] != "codex-session-start"]
            else:
                row = next(s for s in mixed["sources"] if s["id"] == "codex-session-start")
                row["url"] = row["url"].replace(SHA, "c" * 40)
                row["revision"] = "c" * 40
            _, baseline = monitor.run_monitor(before, self.manifest)
            result, _ = monitor.run_monitor(mixed, self.manifest, baseline)
            with self.subTest(mapping=mismatch):
                self.assertNotIn("breaking_change", result["summary"])

    def test_local_source_matchers_are_extracted_instead_of_assumed(self):
        current = CodexProvider(ROOT).local()["hook.event_delivery"]["values"]
        self.assertEqual(current["matchers"]["SessionStart"], "startup|resume|clear|compact")
        legacy = CodexProvider(ROOT).local("0.124.0")["hook.event_delivery"]["values"]
        self.assertEqual(legacy["matchers"]["SessionStart"], "startup|resume|clear")

    def test_optional_file_description_is_informational_only_for_an_exact_addition(self):
        old = """#[derive(Deserialize)]
pub struct HooksFile {
    #[serde(default)]
    pub hooks: HookEventsToml,
}
"""
        addition = (
            '    #[serde(default, skip_serializing_if = "Option::is_none")]\n    pub description: Option<String>,\n'
        )
        new = old.replace("    #[serde(default)]", addition + "    #[serde(default)]")
        before = source_snapshot(self.manifest, {"codex-hook-config": old})
        for suffix, expected in (("", "observed"), ("fn disable_hooks() {}\n", "review_required")):
            after = source_snapshot(self.manifest, {"codex-hook-config": new + suffix}, SHA)
            _, state = monitor.run_monitor(before, self.manifest)
            report, _ = monitor.run_monitor(after, self.manifest, state)
            with self.subTest(extra_runtime_change=suffix):
                self.assertEqual(report["findings"][0]["decision"], expected)
                if expected == "observed":
                    self.assertEqual(report["findings"][0]["analysis_status"], "informational_scope")
                    self.assertEqual(report["findings"][0]["invariants"], [])
                    self.assertIn("description", report["findings"][0]["scope_reason"])
                    self.assertIn("description", monitor.markdown(report))

    def test_guarded_test_hunk_is_informational_but_guard_removal_is_not(self):
        old = """fn production() { run_hooks(); }

#[cfg(test)]
mod tests {
    fn regression() {
        assert_eq!(hook_timeout(), 2);
    }
}
"""
        before = source_snapshot(self.manifest, {"codex-command-runner": old})
        for code, expected in (
            (old.replace("hook_timeout(), 2", "hook_timeout(), 3"), "observed"),
            (old.replace("#[cfg(test)]\n", ""), "review_required"),
            (old.replace("run_hooks()", "skip_hooks()"), "review_required"),
        ):
            after = source_snapshot(self.manifest, {"codex-command-runner": code}, SHA)
            _, state = monitor.run_monitor(before, self.manifest)
            report, _ = monitor.run_monitor(after, self.manifest, state)
            with self.subTest(code=code):
                self.assertEqual(report["findings"][0]["decision"], expected)

    def test_test_scope_cannot_be_manufactured_by_strings_or_shared_line_production(self):
        for old, new, expected in (
            ('let s = r#"#[cfg(test)] mod tests { 2 }"#;\n', 'let s = r#"#[cfg(test)] mod tests { 3 }"#;\n', False),
            (
                "#[cfg(test)] mod tests {} fn production() { run_hooks(); }\n",
                "#[cfg(test)] mod tests {} fn production() { skip_hooks(); }\n",
                False,
            ),
            ("#[cfg(test)]\nmod tests {\n    check();\n}\n", "#[cfg(test)]\nmod tests {\n\n    check();\n}\n", True),
            ("mod tests {\n    check(2);\n}\n", "mod tests {\n    check(3);\n}\n", False),
        ):
            before = {"text": old, "revision": PARENT}
            after = {"id": "fixture", "url": "fixture.rs", "text": new, "revision": SHA, "kind": "source"}
            candidate = monitor.candidates(after, before)[0]
            with self.subTest(old=old):
                self.assertEqual(is_test_only_hunk(candidate, after, before), expected)

    def test_source_helpers_reject_unreachable_facts_unknown_guards_and_raw_strings(self):
        route = """let session_start_source = match &initial_history {
    InitialHistory::Forked(_) if custom_guard() => { codex_hooks::SessionStartSource::Fork }
};"""
        self.assertEqual(session_routes(route), ([], None))
        self.assertEqual(session_routes('let text = r#"' + route + '"#;'), ([], None))
        test_only = """#[cfg(test)] mod tests {
    fn example() {
        let session_start_source = match &initial_history {
            InitialHistory::Forked(_) => codex_hooks::SessionStartSource::Fork,
        };
    }
}"""
        self.assertEqual(session_routes(test_only), ([], None))
        fake = """impl SessionStartSource {
    pub fn as_str(self) -> &'static str {
        return "startup";
        match self { Self::Fork => "fork", }
    }
}
impl StartHookTarget {
    fn matcher_input(&self) -> &str {
        match self {
            Self::SessionStart { source } => source.as_str(),
            Self::SubagentStart { agent_type, .. } => agent_type.as_str(),
        }
    }
}"""
        self.assertEqual(source_matcher_map(fake), ({}, None))

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

    def test_analyzer_upgrade_does_not_hide_a_deny_schema_regression(self):
        before = source_snapshot(self.manifest, {"codex-pre-tool-use-output": deny_schema(["allow", "deny"])})
        after = source_snapshot(self.manifest, {"codex-pre-tool-use-output": deny_schema(["allow"])}, SHA)
        _, state = monitor.run_monitor(before, self.manifest)
        state["signature"] = "previous-analyzer"
        state["cache"] = {"stale": {"must_not_be_used": True}}
        report, updated = monitor.run_monitor(after, self.manifest, state)
        self.assertEqual(report["summary"], {"breaking_change": 1})
        self.assertFalse(updated["cache"])

    def test_optional_property_additions_do_not_invent_a_correlation_change(self):
        before = source_snapshot(self.manifest, {"codex-pre-tool-use-input": input_schema()})
        after = source_snapshot(
            self.manifest,
            {"codex-pre-tool-use-input": input_schema(agent_id={"type": "string"}, agent_type={"type": "string"})},
            SHA,
        )
        _, state = monitor.run_monitor(before, self.manifest)
        report, _ = monitor.run_monitor(after, self.manifest, state)
        self.assertEqual(report["summary"], {"observed": 1})
        checks = report["findings"][0]["invariants"]
        self.assertEqual(
            {c["invariant_id"]: c["verdict"] for c in checks},
            {"hook.payload": "compatible", "hook.correlation": "compatible"},
        )
        proof = next(c for c in checks if c["invariant_id"] == "hook.correlation")["upstream_claims"][0]
        self.assertEqual(proof["kind"], "fields_added")
        self.assertEqual({r["revision"] for r in proof["evidence"]}, {SHA, PARENT})
        self.assertFalse(checks[0]["runtime_verified"])

    def test_new_integer_type_conflicts_with_a_consumed_string(self):
        before = source_snapshot(self.manifest, {"codex-pre-tool-use-input": input_schema()})
        bad = input_schema().replace('"type": "string"', '"type": "integer"', 1)
        after = source_snapshot(self.manifest, {"codex-pre-tool-use-input": bad}, SHA)
        _, state = monitor.run_monitor(before, self.manifest)
        report, _ = monitor.run_monitor(after, self.manifest, state)
        self.assertIn("breaking_change", report["summary"])

    def test_schema_constraints_beside_refs_are_not_ignored(self):
        text = json.dumps(
            {
                "properties": {"x": {"$ref": "#/definitions/X", "enum": ["allow"]}},
                "definitions": {"X": {"type": "string", "enum": ["allow", "deny"]}},
            }
        )
        node, _ = schema_property(text, ["x"])
        self.assertIsNone(node)

    def test_deny_schema_checks_const_and_type_alongside_enum(self):
        before = source_snapshot(self.manifest, {"codex-pre-tool-use-output": deny_schema(["allow", "deny"])})
        for constraint in ({"const": "allow"}, {"type": "boolean"}):
            doc = json.loads(deny_schema(["allow", "deny"]))
            doc["properties"]["hookSpecificOutput"]["properties"]["permissionDecision"].update(constraint)
            after = source_snapshot(self.manifest, {"codex-pre-tool-use-output": json.dumps(doc, indent=2)}, SHA)
            _, state = monitor.run_monitor(before, self.manifest)
            report, _ = monitor.run_monitor(after, self.manifest, state)
            with self.subTest(constraint=constraint):
                self.assertIn("breaking_change", report["summary"])

    def test_event_specific_output_tag_is_compared_to_the_actual_emitter(self):
        responses = CodexProvider(ROOT).local()["hook.decision"]["values"]["responses"]
        self.assertEqual(responses["PreToolUse"].get("hookSpecificOutput.hookEventName"), "PreToolUse")
        doc = json.loads(deny_schema(["allow", "deny"]))
        props = doc["properties"]["hookSpecificOutput"]["properties"]
        props["hookEventName"] = {"type": "string", "enum": ["PreToolUse", "PostToolUse"]}
        before = source_snapshot(self.manifest, {"codex-pre-tool-use-output": json.dumps(doc, indent=2)})
        for tag, expected in (("PreToolUse", "observed"), ("PostToolUse", "breaking_change")):
            after_doc = copy.deepcopy(doc)
            after_doc["properties"]["hookSpecificOutput"]["properties"]["hookEventName"] = {
                "type": "string",
                "const": tag,
            }
            after = source_snapshot(self.manifest, {"codex-pre-tool-use-output": json.dumps(after_doc, indent=2)}, SHA)
            _, state = monitor.run_monitor(before, self.manifest)
            report, _ = monitor.run_monitor(after, self.manifest, state)
            with self.subTest(tag=tag):
                self.assertEqual(report["summary"], {expected: 1})

    def test_nonliteral_response_tag_cannot_borrow_a_comment_or_raw_string(self):
        for fake in ('/* "hookEventName": "PreToolUse" */', '_ = `"hookEventName": "PreToolUse"`'):
            provider = CodexProvider(ROOT)
            path, text, _ = provider.sources["profile"]
            old = '"hookEventName":            "PreToolUse",'
            self.assertIn(old, text)
            text = text.replace(old, '"hookEventName": event,', 1)
            text = text.replace('case "PreToolUse":', 'case "PreToolUse":\n' + fake, 1)
            revision = monitor.digest(text)
            provider.sources["profile"] = (path, text, revision)
            provider.texts[(path, revision)] = text
            with self.subTest(fake=fake):
                self.assertFalse(provider.local()["hook.decision"]["verified"])

    def test_unmodeled_deny_constraints_cannot_manufacture_compatibility(self):
        before = source_snapshot(self.manifest, {"codex-pre-tool-use-output": deny_schema(["allow"])})
        doc = json.loads(deny_schema(["allow", "deny"]))
        doc["properties"]["hookSpecificOutput"]["properties"]["permissionDecision"]["pattern"] = "^allow$"
        after = source_snapshot(self.manifest, {"codex-pre-tool-use-output": json.dumps(doc, indent=2)}, SHA)
        _, state = monitor.run_monitor(before, self.manifest)
        report, _ = monitor.run_monitor(after, self.manifest, state)
        self.assertEqual(report["summary"], {"review_required": 1})
        self.assertNotIn("compatible", report["invariant_summary"])

    def test_additive_proof_refuses_companion_constraints_and_existing_field_changes(self):
        before = json.loads(input_schema())
        base = json.loads(input_schema(agent_id={"type": "string"}))
        for mutation in ("required", "pairing_type", "definitions", "conditional", "python_equal_values"):
            old, new = copy.deepcopy(before), copy.deepcopy(base)
            if mutation == "required":
                new["required"].append("agent_id")
            elif mutation == "pairing_type":
                new["properties"]["tool_use_id"]["type"] = "integer"
            elif mutation == "definitions":
                new["definitions"] = {"Changed": {"type": "string"}}
            elif mutation == "conditional":
                old["allOf"] = new["allOf"] = [{"if": {"required": ["agent_id"]}}]
            else:
                old["properties"]["meta"] = {"const": True}
                new["properties"]["meta"] = {"const": 1}
            with self.subTest(mutation=mutation):
                self.assertEqual(schema_added_fields(new, old), [])

    def test_strict_schema_parser_rejects_duplicate_nonfinite_and_excessive_nesting(self):
        for text in (
            '{"title":"old", "title":"new"}',
            '{"default":NaN}',
            '{"default":1e999}',
            '{"default":' + "9" * 130 + "}",
            "[" * 65 + "0" + "]" * 65,
        ):
            with self.subTest(text=text[:80]), self.assertRaises(InvariantError):
                schema_document(text)
        self.assertEqual(schema_document('{"description":"[\\"{}"}'), {"description": '["{}'})

    def test_ambiguous_schema_is_a_gap_not_a_break_or_a_compatibility_claim(self):
        before = source_snapshot(self.manifest, {"codex-pre-tool-use-input": input_schema()})
        duplicate = input_schema().replace('"title":', '"title":"ignored", "title":', 1)
        after = source_snapshot(self.manifest, {"codex-pre-tool-use-input": duplicate}, SHA)
        _, state = monitor.run_monitor(before, self.manifest)
        report, _ = monitor.run_monitor(after, self.manifest, state)
        self.assertEqual(report["outcome"], "incomplete")
        self.assertNotIn("breaking_change", report["summary"])
        self.assertNotIn("compatible", report["invariant_summary"])

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

    def test_rust_test_regions_preserve_production_timeout_facts_and_breaking_verdicts(self):
        declaration = "const SESSION_END_MAX_TIMEOUT_SEC: u64 = 1;"
        prefixes = (
            "#[cfg(test)]\nuse crate::test_support;\n",
            "#[cfg(test)]\npub(crate) use crate::{test_support, nested::{helper, other}};\n",
            "#[cfg(windows)]\nuse crate::platform_support;\n",
            '#[cfg_attr(feature = "fixture", cfg(unix))]\nuse crate::platform_support;\n',
            "# [ cfg ( /* test-only */ test ) ]\nuse crate::test_support;\n",
            'const MARKER: &str = "#[cfg(test)]";\n',
            'const MARKER: &str = r##"#[cfg(test)] mod tests { }"##;\n',
            '#[cfg(test)]\nmod tests {\nfn sample() { let braces = "} {"; }\n}\n',
            "#[cfg(test)]\n#[test]\nasync fn sample() { if true { check(); } }\n",
            "#[cfg(test)] mod tests {\nconst SESSION_END_DEFAULT_TIMEOUT_SEC: u64 = 1;\n}\n"
            "#[cfg(test)] fn sample() { const SESSION_END_MAX_TIMEOUT_SEC: u64 = 0; }\n",
            "#[cfg(unix)] mod platform {\nconst SESSION_END_DEFAULT_TIMEOUT_SEC: u64 = 1;\n}\n",
            "#[cfg(not(test))]\nconst SESSION_END_DEFAULT_TIMEOUT_SEC: u64 = 1;\n",
            "#[cfg(test)]\nconst SESSION_END_DEFAULT_TIMEOUT_SEC: u64 = 1;\n",
            "#[cfg(test)]\nstruct Fixture<const N: usize = { 1 + 2 }> { bytes: [u8; N] }\n",
        )
        for prefix in prefixes:
            with self.subTest(prefix=prefix):
                code = prefix + declaration + "\n"
                after = source_snapshot(self.manifest, {"codex-session-end": code}, SHA)
                source = next(s for s in after["sources"] if s["id"] == "codex-session-end")
                claims = CodexProvider(ROOT).extract(source)
                self.assertEqual([(c["kind"], c["value"]) for c in claims], [("hard_timeout_seconds", 1)])
                ref = claims[0]["evidence"][0]
                self.assertEqual(ref["quote"], declaration)
                self.assertEqual(ref["start"], len(prefix))
                self.assertEqual(ref["end"], len(prefix) + len(declaration))
                self.assertEqual(ref["line"], prefix.count("\n") + 1)
                before = source_snapshot(self.manifest, {"codex-session-end": code.replace("= 1;", "= 30;")})
                _, state = monitor.run_monitor(before, self.manifest)
                report, _ = monitor.run_monitor(after, self.manifest, state)
                self.assertEqual(report["summary"], {"breaking_change": 1})
                self.assertEqual(report["ai_calls"], 0)
                check = next(
                    c for f in report["findings"] for c in f["invariants"] if c["verdict"] == "breaking_change"
                )
                self.assertEqual(check["invariant_id"], "hook.execution")
                self.assertFalse(check["runtime_verified"])

    def test_rust_test_declarations_cannot_supply_production_timeout_facts(self):
        declaration = "const SESSION_END_MAX_TIMEOUT_SEC: u64 = 1;"
        for code in (
            "#[cfg(test)]\nmod tests {\n" + declaration + "\n}\n",
            "#[cfg(test)]\n#[test]\nfn sample() {\n" + declaration + "\n}\n",
            "#[cfg(test)]\n" + declaration + "\n",
        ):
            source = {"id": "codex-session-end", "url": "fixture:session_end.rs", "revision": SHA, "text": code}
            with self.subTest(code=code):
                self.assertEqual(CodexProvider(ROOT).extract(source), [])

    def test_malformed_or_unrecognized_rust_test_guards_remain_uncertain(self):
        declaration = "const SESSION_END_MAX_TIMEOUT_SEC: u64 = 1;\n"
        for guard in (
            "#[cfg(test)]\nmod tests {\n",
            "#[cfg(test)\n",
            "#[cfg(test]\n",
            '#[cfg(any(test, feature = "fixture"))]\n',
            '#[cfg_attr(test, cfg(feature = "fixture"))]\n',
            "#![cfg(test)]\n",
            "#[cfg(test)]\nunsupported! {\n",
            "#[cfg(test)]\nuse crate::{helper;\n",
            "#[cfg(test)]\nfn sample() { (] }\n",
        ):
            with self.subTest(guard=guard):
                code = guard + declaration
                before = source_snapshot(self.manifest, {"codex-session-end": code.replace("= 1;", "= 30;")})
                after = source_snapshot(self.manifest, {"codex-session-end": code}, SHA)
                source = next(s for s in after["sources"] if s["id"] == "codex-session-end")
                self.assertEqual(CodexProvider(ROOT).extract(source), [])
                _, state = monitor.run_monitor(before, self.manifest)
                report, _ = monitor.run_monitor(after, self.manifest, state)
                self.assertEqual(report["summary"], {"review_required": 1})
                self.assertNotIn("compatible", report["invariant_summary"])

    def test_previous_rust_test_declarations_cannot_establish_retirements(self):
        old = """pub struct HookEventsToml {
    #[serde(rename = "PreToolUse", default)]
    pub pre_tool_use: Vec<MatcherGroup>,
}
pub enum HookHandlerConfig {
    #[serde(rename = "command")]
    Command { command: String },
}
"""
        new = """pub struct HookEventsToml {
    #[serde(rename = "Stop", default)]
    pub stop: Vec<MatcherGroup>,
}
pub fn matcher_groups_mut(&mut self) {
    [(Event::Stop, &mut self.stop)]
    }
pub enum HookHandlerConfig {
    Other { command: String },
}
"""
        source = {"id": "codex-hook-config", "url": "fixture:hook_config.rs", "revision": SHA, "text": new}
        for prefix, suffix in (("#[cfg(test)] mod tests {\n", "}\n"), ("#[cfg(test)\n", "")):
            previous = {**source, "revision": PARENT, "text": prefix + old + suffix}
            with self.subTest(prefix=prefix):
                claims = CodexProvider(ROOT).extract(source, previous)
                self.assertEqual([c["kind"] for c in claims], ["event_inventory"])

    def test_removing_a_formatted_rust_test_guard_is_not_informational(self):
        for guard in ("# [ cfg (test) ]\n", "#[cfg(\n    test\n)]\n", "#\n[cfg(test)]\n"):
            old = guard + "mod tests {\n    fn sample() {}\n}\n"
            new = old.removeprefix(guard)
            before = {"text": old, "revision": PARENT}
            after = {"id": "fixture", "url": "fixture.rs", "text": new, "revision": SHA, "kind": "source"}
            candidate = monitor.candidates(after, before)[0]
            with self.subTest(guard=guard):
                self.assertFalse(is_test_only_hunk(candidate, after, before))

    def test_other_rust_conditionals_only_exclude_their_own_declarations(self):
        timeout = "const SESSION_END_MAX_TIMEOUT_SEC: u64 = 1;\n"
        default = "const SESSION_END_DEFAULT_TIMEOUT_SEC: u64 = 30;\n"
        for guard in (
            "#[cfg(unix)]\n",
            "#[cfg(not(test))]\n",
            '#[cfg(any(test, feature = "fixture"))]\n',
            '#[cfg_attr(feature = "fixture", cfg(unix))]\n',
        ):
            for body in (timeout, "mod platform {\n" + timeout + "}\n"):
                with self.subTest(guard=guard, body=body):
                    code = guard + body
                    self.assertEqual(rust_test_spans(code), [])
                    source = {
                        "id": "codex-session-end",
                        "url": "fixture.rs",
                        "revision": SHA,
                        "text": default + code + default.replace("DEFAULT", "MAX"),
                    }
                    claims = CodexProvider(ROOT).extract(source)
                    self.assertEqual(
                        [(c["kind"], c["value"]) for c in claims],
                        [("hard_timeout_seconds", 30), ("default_timeout_seconds", 30)],
                    )
                    old = code.replace("= 1;", "= 30;")
                    before = {"text": old, "revision": PARENT}
                    after = {"id": "fixture", "url": "fixture.rs", "text": code, "revision": SHA, "kind": "source"}
                    candidate = monitor.candidates(after, before)[0]
                    self.assertFalse(is_test_only_hunk(candidate, after, before))

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

    def test_history_sampling_includes_core_only_dispatch_changes(self):
        calls = []

        def fetch(url, **options):
            monitor.checked_url(url)
            calls.append(url)
            rows = []
            if "core%2Fsrc%2Fsession%2Fsession.rs" in url:
                rows = [
                    {
                        "sha": SHA,
                        "parents": [{"sha": PARENT}],
                        "commit": {
                            "committer": {"date": "2026-10-16T00:00:00Z"},
                            "message": "Core-only source transition",
                        },
                    }
                ]
            return json.dumps(rows)

        report = collect_history(self.manifest, fetch, lambda m, f, rev: source_snapshot(m, revision=rev), count=1)
        self.assertEqual(report["cases"][0]["commit"], SHA)
        self.assertIn("codex-rs/core/src/session/session.rs", report["sampled_paths"])
        self.assertLessEqual(len(calls), 8)

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
        self.assertEqual(report["gaps"][0]["availability"], "no_parent_baseline")
        both = copy.deepcopy(broken)
        both["snapshots"][SHA]["sources"].pop()
        report = replay_history(both, self.manifest, monitor.run_monitor, root=ROOT)
        self.assertTrue(all(gap["availability"] == "unavailable_in_both_revisions" for gap in report["gaps"]))

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
