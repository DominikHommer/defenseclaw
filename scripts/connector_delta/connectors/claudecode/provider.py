#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Claude-specific extraction into the monitor's shared invariant vocabulary.

Only bounded, recognized source shapes become facts. Unknown Go writer shapes,
unrecognized Markdown and omitted examples remain unverified. This is not a Go
interpreter, and downloaded content is never imported or executed.
"""

from __future__ import annotations

import json
import re

from scripts.connector_delta import invariants as engine
from scripts.connector_delta import platforms
from scripts.connector_delta.provider import CONFIG, CommandHookProvider, _block, _mask_go


class ClaudeProvider(CommandHookProvider):
    def __init__(self, root, binding_path=CONFIG / "connectors/claudecode/bindings.json"):
        super().__init__(root, binding_path, "claudecode")

    def local(self, version=None):
        contract = self._contract(version)
        if contract is None:
            return {
                row["id"]: self._binding(row["id"], {"unsupported_agent_version": version}, [], False)
                for row in self.spec["bindings"]
            }
        if contract["contract_id"] in self.local_cache:
            return self.local_cache[contract["contract_id"]]
        registry_text = self.sources["registry"][1]
        registry_start = registry_text.index('"contract_id": "' + contract["contract_id"] + '"')
        registry_start = registry_text.rfind("{", 0, registry_start)
        decoder = json.JSONDecoder()
        _, consumed = decoder.raw_decode(registry_text[registry_start:])
        registry_end = registry_start + consumed
        # Bound evidence to this version's contract, not other connectors.
        registry_ref = self._ref("registry", (registry_start, registry_end))
        registration = self.sources["registration"][1]
        config_root, root_ref = self._function("registration", "config_root_function")
        config_path, path_ref = self._function("registration", "config_path_function")
        directory = re.search(r'filepath\.Join\(userHomeDir\(\),\s*"([^"/]+)"\)', config_root)
        filename = re.search(r'filepath\.Join\(claudeCodeConfigDir\(\),\s*"([^"/]+)"\)', config_path)
        paths = [f"~/{directory[1]}/{filename[1]}"] if directory and filename else []
        discovery_verified = bool(paths and paths[0] in contract.get("hook_config_path_templates", []))
        events = contract["events"]
        event_matches = list(re.finditer(r'newClaudeCodeHookGroup\("([A-Za-z]+)"[^\n]*', registration))
        registered = {match[1] for match in event_matches}
        event_refs = [self._ref("registration", match.span()) for match in event_matches if match[1] in events]
        event_verified = set(events) <= registered
        matrix_span = _block(registration, "appendClaudeCodeHookGroups")
        matrix = registration[slice(*matrix_span)] if matrix_span else ""
        writer_match = re.search(r'settings\["(hooks)"\]\s*=\s*hooks', registration)
        keys = [writer_match[1]] if writer_match else []
        handler_type = re.search(r'"type"\s*:\s*"([a-z]+)"', matrix)
        if handler_type:
            keys += [f"handler.type={handler_type[1]}"]
        request = self.sources["request"][1]
        request_span = _block(request, self.spec["selectors"]["request_struct"], struct=True)
        fields = {}
        request_verified = True
        if request_span:
            for match in re.finditer(
                r'^\s*\w+\s+(.+?)\s+`json:"([^",]+)(?:,[^"]*)?"`', request[slice(*request_span)], re.MULTILINE
            ):
                go_type, name = match[1].strip(), match[2]
                if name == "-":
                    continue
                mapped = (
                    "string"
                    if go_type == "string"
                    else "boolean"
                    if go_type == "bool"
                    else "number"
                    if go_type in {"int", "int64", "float64"}
                    else "object"
                    if go_type.startswith("map[")
                    else None
                )
                if mapped:
                    fields[name] = [mapped, "null"]
                elif go_type == "interface{}":
                    fields[name] = ["string", "boolean", "number", "object", "array", "null"]
                else:
                    request_verified = False
        response, response_ref = self._function("profile", "response_function")
        block_start = response.find('if action == "block"')
        if block_start >= 0:
            masked = _mask_go(response)
            opening = masked.find("{", block_start)
            depth, closing = 0, None
            for index in range(opening, len(masked)):
                depth += (masked[index] == "{") - (masked[index] == "}")
                if depth == 0:
                    closing = index + 1
                    break
            response = response[block_start:closing] if closing else ""
        else:
            response = ""
        cases = list(re.finditer(r'\bcase\s+((?:"[A-Za-z]+"\s*,?\s*)+)\s*:', response))
        responses = {}
        for index, match in enumerate(cases):
            body = response[
                match.end() : cases[index + 1].start()
                if index + 1 < len(cases)
                else response.find("default:", match.end())
            ]
            pairs = dict(re.findall(r'"([A-Za-z]+)"\s*:\s*"([A-Za-z]+)"', body))
            mapping = {}
            if '"hookSpecificOutput"' in body:
                for key in ("permissionDecision", "action"):
                    if key in pairs:
                        mapping[f"hookSpecificOutput.{key}"] = pairs[key]
                if "behavior" in pairs and '"decision"' in body:
                    mapping["hookSpecificOutput.decision.behavior"] = pairs["behavior"]
            for event in re.findall(r'"([A-Za-z]+)"', match[1]):
                if mapping:
                    responses[event] = mapping
        # The default deny is emitted only for the remaining enforcement events.
        default_output = response[response.find("default:") :]
        if re.search(r'"decision":\s*"block"', default_output):
            explicit_cases = {event for match in cases for event in re.findall(r'"([A-Za-z]+)"', match[1])}
            for event in contract["capabilities"]["block_events"]:
                if event not in explicit_cases:
                    responses[event] = {"decision": "block"}
        group, group_ref = self._function("registration", "registration_function")
        async_event = re.search(r'async:\s*eventType\s*==\s*"([A-Za-z]+)"', group)
        barrier_events = [
            event for event in contract["capabilities"]["block_events"] if not async_event or event != async_event[1]
        ]
        timeout, timeout_ref = self._function("execution", "timeout_function")
        default = re.search(r"default:\s*return\s+(\d+)", timeout)
        timeouts = {event: int(default[1]) for event in events} if default else {}
        for match in re.finditer(r'case\s+((?:"[A-Za-z]+"\s*,?\s*)+):\s*return\s+(\d+)', timeout):
            for event in re.findall(r'"([A-Za-z]+)"', match[1]):
                timeouts[event] = int(match[2])
        failure_text = self.sources["failure"][1]
        failure = re.search(r'"claudecode":\s*\{([\s\S]*?)\n\s*\},', failure_text)
        exit_constant = re.search(r"\bconst blockExit\s*=\s*2\b", self.sources["execution"][1])
        failure_verified = bool(
            failure and re.search(r"unreachableStrict:\s*failResult\{exit:\s*blockExit\}", failure[1]) and exit_constant
        )
        paired = contract.get("tool_call_lifecycle", {}).get("invocation_id_authority") == "paired-id"
        result = {
            "hook.discovery": self._binding(
                "hook.discovery",
                {
                    "paths": paths,
                    "environment": "local",
                    "config_root_override": "CLAUDE_CONFIG_DIR"
                    if 'os.Getenv("CLAUDE_CONFIG_DIR")' in config_root
                    else None,
                },
                [root_ref, path_ref, registry_ref],
                discovery_verified,
            ),
            "hook.registration": self._binding(
                "hook.registration",
                {"keys": keys},
                [
                    self._ref("registration", matrix_span) if matrix_span else None,
                    self._ref("registration", writer_match.span()) if writer_match else None,
                ],
                bool(keys and handler_type),
            ),
            "hook.event_delivery": self._binding(
                "hook.event_delivery", {"events": events}, [registry_ref, *event_refs], event_verified
            ),
            "hook.payload": self._binding(
                "hook.payload",
                {"events": events, "fields": fields, "required_fields": ["hook_event_name", "tool_name", "tool_input"]},
                [self._ref("request", request_span) if request_span else None],
                bool(fields) and request_verified,
            ),
            "hook.decision": self._binding(
                "hook.decision", {"events": list(responses), "responses": responses}, [response_ref], bool(responses)
            ),
            "hook.execution": self._binding(
                "hook.execution",
                {
                    "events": events,
                    "barrier_events": barrier_events,
                    "expected_phases": {
                        event: "before"
                        for event in contract.get("tool_call_lifecycle", {}).get("pre_proposal_events", [])
                    },
                    "timeouts": timeouts,
                },
                [group_ref, timeout_ref, registry_ref],
                bool(async_event and default),
            ),
            "hook.failure": self._binding(
                "hook.failure",
                {"events": barrier_events, "blocking_exit_codes": [2]},
                [
                    self._ref("failure", failure.span()) if failure else None,
                    self._ref("execution", exit_constant.span()) if exit_constant else None,
                ],
                failure_verified,
            ),
            "hook.correlation": self._binding(
                "hook.correlation",
                {
                    "events": contract.get("tool_call_lifecycle", {}).get("pre_proposal_events", [])
                    + contract.get("tool_call_lifecycle", {}).get("authoritative_success_events", []),
                    "fields": {key: fields[key] for key in ("tool_use_id",) if key in fields},
                    "required_fields": ["tool_use_id"],
                },
                [registry_ref, self._ref("request", request_span) if request_span else None],
                paired and "tool_use_id" in fields,
            ),
        }
        self.local_cache[contract["contract_id"]] = result
        return result

    def extract(self, text, artifact, revision, *, release=False, base=0, full_text=None):
        full_text = full_text if full_text is not None else text
        self.texts[(artifact, revision)] = full_text
        claims = []

        def local_scope(match):
            # Scoped/conditional/fix/example sentences must not become a
            # retirement claim for the default local command-hook contract.
            start = max(text.rfind("\n", 0, match.start()), text.rfind(". ", 0, match.start())) + 1
            end = text.find("\n", match.end())
            sentence = text[start : end if end >= 0 else len(text)].lower()
            prefix = text[start : match.start()].lstrip().removeprefix("- ").strip()
            return prefix in {"", "The", "the"} and not re.search(
                r"\b(cloud|remote|plugin|project|managed|mod hooks?|if|would|example|fixed|previously)\b", sentence
            )

        def add(invariant_id, kind, value, match, authority="explicit_statement", **extra):
            start, end = (match.start(), match.end()) if hasattr(match, "start") else match
            if authority == "explicit_statement" and (not local_scope(match) or text[:start].count("```") % 2):
                return
            ref = engine.evidence(
                full_text,
                start + base,
                end + base,
                artifact=artifact,
                revision=revision,
                role="upstream",
                authority=authority,
            )
            claims.append(
                {
                    "invariant_id": invariant_id,
                    "kind": kind,
                    "value": value,
                    "authority": authority,
                    "evidence": [ref],
                    **extra,
                }
            )

        # Explicit retirement is required. A path missing from a table is NOT retirement.
        patterns = [
            r"(?:Claude Code |Command )?[Hh]ooks? (?:are |is )?no longer (?:loaded|read) from `([^`]+)`",
            r"`([^`]+)` is no longer (?:read|loaded) for (?:command )?hooks",
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, text):
                if local_scope(match):
                    add("hook.discovery", "retired_path", match[1], match)
        for match in re.finditer(
            r"[Hh]ooks? (?:are |is )?(?:now )?(?:loaded|read) only from (`[^`]+`(?:\s*(?:,|or|and)\s*`[^`]+`)*)", text
        ):
            if local_scope(match):
                add("hook.discovery", "exclusive_paths", re.findall(r"`([^`]+)`", match[1]), match)
        for match in re.finditer(
            r"(?:The )?(?:top-level |registration )?`([A-Za-z_]+)` (?:registration )?key "
            r"is no longer (?:accepted|read|supported)",
            text,
        ):
            add("hook.registration", "retired_registration_key", match[1], match)
        for match in re.finditer(r"`([a-z]+)` hook handler type is no longer accepted", text):
            add("hook.registration", "retired_registration_key", "handler.type=" + match[1], match)
        for match in re.finditer(
            r"(?:The )?`([A-Z][A-Za-z]+)` (?:hook )?event (?:has been removed|is removed|no longer fires)", text
        ):
            if not text[max(0, match.start() - 12) : match.start()].lower().endswith("fixed "):
                add("hook.event_delivery", "event_removed", None, match, event=match[1])
        for match in re.finditer(r"Added (?:a )?`([A-Z][A-Za-z]+)` hook(?: event)?", text):
            add("hook.event_delivery", "event_added", None, match, event=match[1])
        for match in re.finditer(
            r"`([A-Z][A-Za-z]+)` hooks? (?:now )?(?:runs?|fires?) (before|after) (?:the |a )?tool (?:call )?executes",
            text,
        ):
            add("hook.execution", "event_phase", match[2], match, event=match[1])
        for match in re.finditer(r"`([A-Z][A-Za-z]+)` hooks? (?:now )?runs? (asynchronously|synchronously)", text):
            add("hook.execution", "synchronous", match[2] == "synchronously", match, event=match[1])
        for match in re.finditer(
            r"`([A-Z][A-Za-z]+)` (?:hooks? )?(hard|default) timeout (?:is|is now|changes to) (\d+) seconds", text
        ):
            add("hook.execution", f"{match[2]}_timeout_seconds", int(match[3]), match, event=match[1])
        for match in re.finditer(
            r"`([A-Z][A-Za-z]+)` (?:hook )?`([a-z_]+)` (?:field )?(?:is now|has type|changes type to) "
            r"(?:an? )?(string|object|array|number|boolean)",
            text,
        ):
            add("hook.payload", "field_type", match[3], match, event=match[1], field=match[2])
            if match[2] == "tool_use_id":
                add("hook.correlation", "field_type", match[3], match, event=match[1], field=match[2])
        for match in re.finditer(
            r"`([A-Z][A-Za-z]+)` (?:hook )?`([a-z_]+)` (?:field )?is no longer (?:sent|provided)", text
        ):
            add("hook.payload", "field_removed", None, match, event=match[1], field=match[2])
            if match[2] == "tool_use_id":
                add("hook.correlation", "field_removed", None, match, event=match[1], field=match[2])
        for match in re.finditer(
            r'`([A-Z][A-Za-z]+)` (?:hooks? )?(?:now )?(ignores?|accepts?) `([A-Za-z.]+):\s*"([A-Za-z]+)"`', text
        ):
            field = match[3] if "." in match[3] or match[3] == "decision" else "hookSpecificOutput." + match[3]
            add(
                "hook.decision",
                "decision_rejected" if match[2].startswith("ignore") else "decision_accepted",
                match[4],
                match,
                event=match[1],
                field=field,
            )
        for match in re.finditer(
            r"`([A-Z][A-Za-z]+)` (?:hooks? )?exit code (\d+) (no longer blocks|blocks) "
            r"(?:the |a )?(?:tool call|action)",
            text,
        ):
            add(
                "hook.failure", "exit_code_blocks", match[3] == "blocks", match, event=match[1], exit_code=int(match[2])
            )
        for match in re.finditer(
            r"(?:Changed hooks: )?`updatedInput` from (PreToolUse) and PermissionRequest hooks is now validated", text
        ):
            for event in ("PreToolUse", "PermissionRequest"):
                add(
                    "hook.decision",
                    "response_field_validated",
                    None,
                    match,
                    event=event,
                    field="hookSpecificOutput.updatedInput",
                )

        if release:
            return claims  # Never borrow current docs as historical release evidence.

        # Recognized authoritative Markdown tables. Scope paths to local user
        # settings; project, plugin and cloud locations are different bindings.
        locations = re.search(r"^### Hook locations\s*\n([\s\S]*?)(?=^### |\Z)", text, re.MULTILINE)
        if locations:
            rows = list(re.finditer(r"^\| `([^`]+)` \| ([^|]+)\|[^\n]*", locations[1], re.MULTILINE))
            user_paths = [row[1] for row in rows if row[1].startswith("~/") and "All your projects" in row[2]]
            if user_paths:
                add("hook.discovery", "accepted_paths", user_paths, locations.span(), "contract_table")
        event_table = re.search(r"^\| Event \| When it fires \|\s*\n([\s\S]*?)(?=\n\s*\n|\Z)", text, re.MULTILINE)
        if event_table:
            rows = list(re.finditer(r"^\| `([A-Z][A-Za-z]+)` \| ([^\n]+)", event_table[1], re.MULTILINE))
            if rows:
                add(
                    "hook.event_delivery",
                    "event_inventory",
                    [row[1] for row in rows],
                    event_table.span(),
                    "contract_table",
                )
            for row in rows:
                if row[2].startswith(("Before a tool call executes", "After a tool call executes")):
                    span = (event_table.start(1) + row.start(), event_table.start(1) + row.end())
                    add(
                        "hook.execution",
                        "event_phase",
                        "before" if row[2].startswith("Before") else "after",
                        span,
                        "contract_table",
                        event=row[1],
                    )
        for section in re.finditer(
            r"^#### ([A-Z][A-Za-z]+) (input|decision control)\s*\n([\s\S]*?)(?=^#{1,4} |\Z)", text, re.MULTILINE
        ):
            event, kind, body = section[1], section[2], section[3]
            if kind == "input":
                # A typed table is a contract; a JSON example is not exhaustive.
                typed = re.search(r"^\| Field \| Type \|[^\n]*\n([\s\S]*?)(?=\n\s*\n|\Z)", body, re.MULTILINE)
                if typed:
                    for row in re.finditer(
                        r"^\| `([a-z_]+)` \| `(string|object|array|number|boolean)` \|[^\n]*", typed[1], re.MULTILINE
                    ):
                        offset = section.start(3) + typed.start(1)
                        span = (offset + row.start(), offset + row.end())
                        add("hook.payload", "field_type", row[2], span, "declared_schema", event=event, field=row[1])
                        if row[1] == "tool_use_id":
                            add(
                                "hook.correlation",
                                "field_type",
                                row[2],
                                span,
                                "declared_schema",
                                event=event,
                                field=row[1],
                            )
                else:
                    for block in re.finditer(r"```json[^\n]*\n([\s\S]*?)\n```", body):
                        try:
                            example = json.loads(block[1])
                        except json.JSONDecodeError:
                            continue
                        if isinstance(example, dict):
                            for field, value in example.items():
                                field_type = (
                                    "null"
                                    if value is None
                                    else "boolean"
                                    if isinstance(value, bool)
                                    else "object"
                                    if isinstance(value, dict)
                                    else "array"
                                    if isinstance(value, list)
                                    else "number"
                                    if isinstance(value, (int, float))
                                    else "string"
                                )
                                offset = section.start(3)
                                add(
                                    "hook.payload",
                                    "field_type",
                                    field_type,
                                    (offset + block.start(), offset + block.end()),
                                    "example",
                                    event=event,
                                    field=field,
                                )
            elif event == "PreToolUse":
                deny = re.search(
                    r'^\| `permissionDecision` \|[^\n]*?`"deny"` prevents the tool call[^\n]*', body, re.MULTILINE
                )
                if deny:
                    offset = section.start(3)
                    add(
                        "hook.decision",
                        "decision_accepted",
                        "deny",
                        (offset + deny.start(), offset + deny.end()),
                        "contract_table",
                        event=event,
                        field="hookSpecificOutput.permissionDecision",
                    )
        return claims

    def checks(self, candidate, source, previous, artifact_classes):
        selected = self.selected(artifact_classes)
        if candidate["kind"] == "document_diff":
            current = self.extract(source["text"], source["url"], source["revision"])
            before = self.extract(previous["text"], previous["url"], previous["revision"]) if previous else []

            def key(claim):
                return json.dumps(
                    {k: claim.get(k) for k in ("invariant_id", "kind", "value", "event", "field", "exit_code")},
                    sort_keys=True,
                )

            old = {key(claim) for claim in before}
            # Only facts changed by this hunk; another hunk's facts cannot
            # manufacture proof for the current finding.
            hunk = re.search(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", candidate["text"])
            start_line = int(hunk[1]) if hunk else 0
            end_line = start_line + (int(hunk[2]) if hunk and hunk[2] else 1)
            claims = [
                claim
                for claim in current
                if key(claim) not in old
                and any(
                    ref["line"] < end_line and ref["line"] + ref["quote"].count("\n") >= start_line
                    for ref in claim["evidence"]
                )
            ]
        elif candidate["kind"] == "release_note":
            start = sum(len(line) for line in source["text"].splitlines(keepends=True)[: candidate.get("line", 1) - 1])
            if not source["text"].startswith(candidate["text"], start):
                start = -1
            claims = (
                self.extract(
                    candidate["text"],
                    source["url"],
                    source["revision"],
                    release=True,
                    base=start,
                    full_text=source["text"],
                )
                if start >= 0
                else []
            )
        else:
            claims = []
        # A normalized fact can identify a dependency missed by keyword rules.
        selected += [claim["invariant_id"] for claim in claims]
        return platforms.evaluate(self, self.local(candidate.get("version")), claims, selected, candidate["text"])
