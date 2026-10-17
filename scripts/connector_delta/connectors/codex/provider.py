# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Codex bindings and bounded source/schema extraction; no upstream code runs."""

from __future__ import annotations

import json
import re

from scripts.connector_delta import invariants as engine
from scripts.connector_delta import platforms
from scripts.connector_delta.provider import CONFIG, CommandHookProvider, _block


def rust_mask(text, comments_only=False):
    """Linear lexical masking, including Rust's nested comments and raw strings."""
    result, index = list(text), 0
    while index < len(text):
        start, comment, end = index, False, index + 1
        if text.startswith("//", index):
            comment = True
            end = text.find("\n", index)
            end = len(text) if end < 0 else end
        elif text.startswith("/*", index):
            comment, depth, end = True, 1, index + 2
            while end < len(text) and depth:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
        else:
            raw = re.match(r'(?:br|r)(#{0,255})"', text[index : index + 260]) if text[index] in {"r", "b"} else None
            char = re.match(r"'(?:\\.|[^'\\\n])'", text[index : index + 8]) if text[index] == "'" else None
            if raw:
                closing = '"' + raw[1]
                closing_at = text.find(closing, index + raw.end())
                end = len(text) if closing_at < 0 else closing_at + len(closing)
            elif char:
                end = index + char.end()
            elif text[index] == '"':
                end = index + 1
                while end < len(text):
                    if text[end] == "\\":
                        end += 2
                    elif text[end] == '"':
                        end += 1
                        break
                    else:
                        end += 1
                end = min(end, len(text))
            else:
                index += 1
                continue
        if comment or not comments_only:
            for position in range(start, end):
                if result[position] != "\n":
                    result[position] = " "
        index = end
    return "".join(result)


def json_span(text, pointer):
    """Resolve object keys to exact source spans, without executing a schema."""
    decoder = json.JSONDecoder()
    start = len(text) - len(text.lstrip())
    value, end = decoder.raw_decode(text, start)
    for wanted in pointer:
        if not isinstance(value, dict):
            return None
        index, found = start + 1, None
        while index < end:
            while index < end and text[index] in " \r\n\t,":
                index += 1
            if text[index] == "}":
                break
            key, index = decoder.raw_decode(text, index)
            while text[index].isspace():
                index += 1
            if text[index] != ":":
                raise engine.InvariantError("invalid schema object")
            index += 1
            while text[index].isspace():
                index += 1
            child_start = index
            child, index = decoder.raw_decode(text, index)
            if key == wanted:
                if found is not None:
                    raise engine.InvariantError("duplicate schema key")
                found = child, child_start, index
        if found is None:
            return None
        value, start, end = found
    return value, start, end


def schema_property(text, fields):
    """Only local refs and single allOf are supported. Unknown shapes stay unknown."""
    pointer, seen = [], set()
    for field in [*fields, None]:
        for _ in range(16):
            found = json_span(text, pointer)
            if found is None:
                return None, pointer
            node = found[0]
            if not isinstance(node, dict):
                return node, pointer
            if any(key in node for key in ("anyOf", "oneOf", "not", "if", "then", "else")):
                return None, pointer
            if "$ref" in node:
                ref = node["$ref"]
                if (
                    not isinstance(ref, str)
                    or not re.fullmatch(r"#/(?:definitions|\$defs)/[A-Za-z0-9_]+", ref)
                    or ref in seen
                ):
                    return None, pointer
                seen.add(ref)
                pointer = ref[2:].split("/")
            elif "allOf" in node:
                if not isinstance(node["allOf"], list) or len(node["allOf"]) != 1:
                    return None, pointer
                # json_span traverses objects only. A single allOf ref can be
                # followed directly; other conjunctions are intentionally unknown.
                child = node["allOf"][0]
                ref = child.get("$ref") if isinstance(child, dict) else None
                if (
                    not isinstance(ref, str)
                    or not re.fullmatch(r"#/(?:definitions|\$defs)/[A-Za-z0-9_]+", ref)
                    or ref in seen
                ):
                    return None, pointer
                seen.add(ref)
                pointer = ref[2:].split("/")
            else:
                break
        else:
            return None, pointer
        if field is None:
            return node, pointer
        properties = node.get("properties", {})
        if not isinstance(properties, dict) or field not in properties:
            return (False if node.get("additionalProperties") is False else None), pointer
        pointer += ["properties", field]
    return None, pointer


class CodexProvider(CommandHookProvider):
    def __init__(self, root, binding_path=CONFIG / "connectors/codex/bindings.json"):
        super().__init__(root, binding_path, "codex")

    def local(self, version=None):
        contract = self._contract(version)
        if contract is None:
            return {
                row["id"]: self._binding(row["id"], {"unsupported_agent_version": version}, [], False)
                for row in self.spec["bindings"]
            }
        if contract["contract_id"] in self.local_cache:
            return self.local_cache[contract["contract_id"]]
        registry_ref = self.registry_ref(contract)
        root, root_ref = self._function("root", "config_root_function")
        path, path_ref = self._function("registration", "config_path_function")
        directory = re.search(r'connectorEnvHomeDir\("CODEX_HOME",\s*"([^"/]+)"\)', root)
        filename = re.search(r'filepath\.Join\(codexHomeDir\(\),\s*"([^"/]+)"\)', path)
        paths = [f"~/{directory[1]}/{filename[1]}"] if directory and filename else []
        registration = self.sources["registration"][1]
        group_block = re.search(r"var codexHookGroups = \[\]codexHookGroup\{([\s\S]*?)^\}", registration, re.MULTILINE)
        group_rows = []
        if group_block:
            for match in re.finditer(r'\{"([A-Za-z]+)",\s*"[^"\n]*",\s*(\d+)\}', group_block[1]):
                group_rows.append(
                    (
                        match[1],
                        int(match[2]),
                        (group_block.start(1) + match.start(), group_block.start(1) + match.end()),
                    )
                )
        teardown = re.search(
            r'var codexSessionEndHookGroup = codexHookGroup\{"(SessionEnd)",\s*"",\s*(\d+)\}', registration
        )
        if teardown:
            group_rows.append((teardown[1], int(teardown[2]), teardown.span()))
        groups = {event: timeout for event, timeout, _ in group_rows}
        events = contract["events"]
        group_refs = [self._ref("registration", span) for event, _, span in group_rows if event in events]
        writer, writer_ref = self._function("registration", "registration_function")
        trust_hash, trust_ref = self._function("registration", "trust_hash_function")
        trust_key, key_ref = self._function("registration", "trust_key_function")
        top_key = re.search(r'cfg\["hooks"\]\s*=\s*hooks', registration)
        handler = re.search(r'"type":\s*"command"', writer)
        request = self.sources["request"][1]
        request_span = _block(request, "codexHookRequest", struct=True)
        fields, request_verified = {}, bool(request_span)
        if request_span:
            for match in re.finditer(
                r'^\s*\w+\s+(.+?)\s+`json:"([^",]+)(?:,[^"]*)?"`', request[slice(*request_span)], re.MULTILINE
            ):
                go_type, name = match[1].strip(), match[2]
                if name == "-":
                    continue
                types = {
                    "string": ["string", "null"],
                    "bool": ["boolean", "null"],
                    "map[string]interface{}": ["object", "null"],
                    "interface{}": ["string", "boolean", "number", "object", "array", "null"],
                }
                if go_type not in types:
                    request_verified = False
                else:
                    fields[name] = types[go_type]
        response, response_ref = self._function("profile", "response_function")
        # Isolate the deny branch; confirm/context branches are different contracts.
        start = response.find('if action == "block"')
        stop = response.find('if rawAction == "confirm"', start)
        response = response[start:stop] if start >= 0 and stop > start else ""
        cases = list(re.finditer(r'case\s+((?:"[A-Za-z]+"\s*,?\s*)+)\s*:', response))
        responses = {}
        for i, case in enumerate(cases):
            body = response[case.end() : cases[i + 1].start() if i + 1 < len(cases) else len(response)]
            mapping = {}
            if re.search(r'"permissionDecision":\s*"deny"', body):
                mapping["hookSpecificOutput.permissionDecision"] = "deny"
            if re.search(r'"behavior":\s*"deny"', body):
                mapping["hookSpecificOutput.decision.behavior"] = "deny"
            if re.search(r'"decision":\s*"block"', body):
                mapping["decision"] = "block"
            if re.search(r'"continue":\s*false', body):
                mapping["continue"] = False
            for event in re.findall(r'"([A-Za-z]+)"', case[1]):
                if mapping and event in contract["capabilities"]["block_events"]:
                    responses[event] = mapping
        failure_text = self.sources["failure"][1]
        failure = re.search(r'"codex":\s*\{([\s\S]*?)\n\s*\},', failure_text)
        constant = re.search(r"\bconst blockExit\s*=\s*2\b", self.sources["execution"][1])
        failure_verified = bool(
            failure and constant and re.search(r"unreachableStrict:\s*failResult\{exit:\s*blockExit\}", failure[1])
        )
        request_ref = self._ref("request", request_span) if request_span else None
        paired = contract["tool_call_lifecycle"]["invocation_id_authority"] == "paired-id"
        result = {
            "hook.discovery": self._binding(
                "hook.discovery",
                {"paths": paths, "config_root_override": "CODEX_HOME"},
                [root_ref, path_ref, registry_ref],
                bool(paths and paths[0] in contract["hook_config_path_templates"]),
            ),
            "hook.registration": self._binding(
                "hook.registration",
                {
                    "keys": ["hooks", "handler.type=command"],
                    "trust_required": contract["contract_id"] != "codex-hooks-v1",
                    "trust_identity": "position-aware state key and canonical handler hash",
                },
                [writer_ref, self._ref("registration", top_key.span()) if top_key else None, trust_ref, key_ref],
                bool(handler and top_key and trust_hash and trust_key),
            ),
            "hook.event_delivery": self._binding(
                "hook.event_delivery", {"events": events}, [registry_ref, *group_refs], set(events) <= set(groups)
            ),
            "hook.payload": self._binding(
                "hook.payload",
                {"events": events, "fields": fields, "required_fields": ["hook_event_name", "tool_name", "tool_input"]},
                [request_ref],
                request_verified,
            ),
            "hook.decision": self._binding(
                "hook.decision",
                {"events": list(responses), "responses": responses},
                [response_ref, registry_ref],
                bool(responses) and set(responses) == set(contract["capabilities"]["block_events"]),
            ),
            "hook.execution": self._binding(
                "hook.execution",
                {
                    "events": events,
                    "barrier_events": contract["capabilities"]["block_events"],
                    "expected_phases": {
                        event: "before" for event in contract["tool_call_lifecycle"]["pre_proposal_events"]
                    },
                    "timeouts": {event: groups[event] for event in events if event in groups},
                },
                [writer_ref, *group_refs, registry_ref],
                set(events) <= set(groups) and '"async"' not in writer,
            ),
            "hook.failure": self._binding(
                "hook.failure",
                {"events": contract["capabilities"]["block_events"], "blocking_exit_codes": [2]},
                [
                    self._ref("failure", failure.span()) if failure else None,
                    self._ref("execution", constant.span()) if constant else None,
                ],
                failure_verified,
            ),
            "hook.correlation": self._binding(
                "hook.correlation",
                {
                    "events": ["PreToolUse", "PostToolUse"],
                    "fields": {key: fields[key] for key in ("tool_use_id",) if key in fields},
                    "required_fields": ["tool_use_id"],
                },
                [request_ref, registry_ref],
                paired and request_verified and "tool_use_id" in fields,
            ),
        }
        self.local_cache[contract["contract_id"]] = result
        return result

    def extract(self, source, previous=None):
        text, artifact, revision = source["text"], source["url"], source["revision"]
        self.texts[(artifact, revision)] = text
        claims = []
        masked = "" if artifact.endswith(".schema.json") else rust_mask(text)

        def add(invariant_id, kind, value, span, **extra):
            if ".schema.json" not in artifact:
                first = re.search(r"\S", text[span[0] : span[1]])
                if first is None or masked[span[0] + first.start()].isspace():
                    return
            ref = engine.evidence(
                text, *span, artifact=artifact, revision=revision, role="upstream", authority="declared_schema"
            )
            claims.append(
                {
                    "invariant_id": invariant_id,
                    "kind": kind,
                    "value": value,
                    "authority": "declared_schema",
                    "evidence": [ref],
                    **extra,
                }
            )

        if ".command." in artifact and ".schema.json" in artifact:
            document = json.loads(text)
            if not isinstance(document, dict):
                return []
            title = document.get("title", "")
            if not isinstance(title, str):
                return []
            slugs = {
                "pre-tool-use": "PreToolUse",
                "post-tool-use": "PostToolUse",
                "permission-request": "PermissionRequest",
                "session-start": "SessionStart",
                "user-prompt-submit": "UserPromptSubmit",
                "subagent-stop": "SubagentStop",
                "pre-compact": "PreCompact",
                "post-compact": "PostCompact",
                "stop": "Stop",
            }
            event = slugs.get(title.split(".command.")[0])
            if not event:
                return []
            if title.endswith(".input"):
                properties = document.get("properties", {})
                if not isinstance(properties, dict):
                    return []
                for field in properties:
                    node, pointer = schema_property(text, [field])
                    types = node.get("type") if isinstance(node, dict) else None
                    types = [types] if isinstance(types, str) else types if isinstance(types, list) else []
                    span = json_span(text, pointer)
                    for value in types:
                        if value in {"string", "number", "boolean", "object", "array", "null"}:
                            add("hook.payload", "field_type", value, span[1:], event=event, field=field)
                            if field == "tool_use_id":
                                add("hook.correlation", "field_type", value, span[1:], event=event, field=field)
                before = json.loads(previous["text"]) if previous else {}
                before = before if isinstance(before, dict) else {}
                if document.get("additionalProperties") is False:
                    for field in set(before.get("properties", {})) - set(properties):
                        add("hook.payload", "field_removed", None, (0, len(text)), event=event, field=field)
                        if field == "tool_use_id":
                            add("hook.correlation", "field_removed", None, (0, len(text)), event=event, field=field)
            elif title.endswith(".output"):
                for field, value in self.local()["hook.decision"]["values"]["responses"].get(event, {}).items():
                    node, pointer = schema_property(text, field.split("."))
                    span = json_span(text, pointer)
                    if span is None or node is None:
                        continue
                    if node is False:
                        add("hook.decision", "decision_rejected", value, span[1:], event=event, field=field)
                    elif isinstance(node, dict) and isinstance(node.get("enum"), list):
                        accepted = any(type(item) is type(value) and item == value for item in node["enum"])
                        kind = "decision_accepted" if accepted else "decision_rejected"
                        add("hook.decision", kind, value, span[1:], event=event, field=field)
                    elif (
                        isinstance(node, dict)
                        and isinstance(node.get("type"), str)
                        and node["type"] != ("boolean" if type(value) is bool else "string")
                    ):
                        add("hook.decision", "decision_rejected", value, span[1:], event=event, field=field)
                    elif isinstance(node, dict) and type(value) is bool and node.get("type") == "boolean":
                        add("hook.decision", "decision_accepted", value, span[1:], event=event, field=field)
            return claims
        # Exclude tests and comments. Unknown syntax does not imply removal.
        code = rust_mask(text, comments_only=True).split("#[cfg(test)]", 1)[0]
        if source["id"] == "codex-home-discovery":
            default = re.search(
                r"None => \{\s*let mut p = home_dir\(\)\.ok_or_else\(\|\| \{[\s\S]*?\}\)\?;"
                r'\s*p\.push\("([^"/]+)"\);\s*AbsolutePathBuf::from_absolute_path\(p\)\s*\}',
                code,
            )
            if default:
                add("hook.discovery", "default_directory", "~/" + default[1], default.span())
        elif source["id"] == "codex-hook-config":
            event_block = re.search(r"pub struct HookEventsToml\s*\{([\s\S]*?)\n\}", code)
            if event_block:
                events = re.findall(r'#\[serde\(rename = "([A-Za-z]+)", default\)\]', event_block[1])
                if events:
                    add("hook.event_delivery", "event_inventory", events, event_block.span())
                    # Unlike a doc inventory, this is the typed config plus its
                    # exhaustive event-to-group dispatch. Require both before
                    # calling an absent old event a removal, and reject aliases.
                    dispatch = re.search(r"pub fn matcher_groups_mut\b([\s\S]*?)\n    \}", code)
                    old_block = (
                        re.search(r"pub struct HookEventsToml\s*\{([\s\S]*?)\n\}", previous["text"])
                        if previous
                        else None
                    )
                    if dispatch and old_block and "alias" not in event_block[1]:
                        dispatched = re.findall(r"\(Event::([A-Za-z]+),\s*&mut self\.", dispatch[1])
                        if set(dispatched) == set(events):
                            old_events = re.findall(r'#\[serde\(rename = "([A-Za-z]+)", default\)\]', old_block[1])
                            for event in set(old_events) - set(events):
                                add("hook.event_delivery", "event_removed", None, event_block.span(), event=event)
            command = re.search(r'#\[serde\(rename = "command"\)\]\s*Command\s*\{', code)
            if command:
                add("hook.registration", "accepted_registration_key", "handler.type=command", command.span())
            elif previous:
                handlers = re.search(r"pub enum HookHandlerConfig\s*\{([\s\S]*?)^\}", code, re.MULTILINE)
                if handlers and 'rename = "command"' in previous["text"] and "alias" not in handlers[1]:
                    add("hook.registration", "retired_registration_key", "handler.type=command", handlers.span())
            if re.search(r"pub struct HooksToml\s*\{\s*#\[serde\(flatten\)\]\s*pub events: HookEventsToml", code):
                match = re.search(r"pub struct HooksToml\s*\{[\s\S]*?pub events: HookEventsToml", code)
                add("hook.registration", "accepted_registration_key", "hooks", match.span())
        elif source["id"] == "codex-hook-discovery":
            inline = re.search(r'let hook_value = layer\.config\.get\("hooks"\)\?\.clone\(\);', code)
            if inline and "CONFIG_TOML_FILE" in code:
                # This proves the key is loaded, not the physical config path:
                # that path depends on config layers outside this function.
                add("hook.registration", "accepted_registration_key", "hooks", inline.span())
        elif source["id"] == "codex-session-end":
            for name, kind in (("MAX", "hard_timeout_seconds"), ("DEFAULT", "default_timeout_seconds")):
                match = re.search(rf"const SESSION_END_{name}_TIMEOUT_SEC:\s*u64\s*=\s*(\d+);", code)
                if match:
                    add("hook.execution", kind, int(match[1]), match.span(), event="SessionEnd")
        elif source["id"] == "codex-pre-tool-runtime":
            branch = re.search(
                r"Some\((\d+)\) if handler\.can_apply_control_effects\(\) => \{([\s\S]*?)\n\s*Some\(exit_code\) =>",
                code,
            )
            if branch and "should_block = true;" in branch[2]:
                add(
                    "hook.failure",
                    "exit_code_blocks",
                    True,
                    branch.span(),
                    event="PreToolUse",
                    exit_code=int(branch[1]),
                )
                if int(branch[1]) != 2 and "HookRunStatus::Failed" in code[branch.end() :]:
                    add("hook.failure", "exit_code_blocks", False, branch.span(), event="PreToolUse", exit_code=2)
        return claims

    def checks(self, candidate, source, previous, artifact_classes):
        current = self.extract(source, previous)
        before = self.extract(previous) if previous else []

        def key(claim):
            return json.dumps(
                {k: claim.get(k) for k in ("invariant_id", "kind", "value", "event", "field", "exit_code")},
                sort_keys=True,
            )

        old = {key(claim) for claim in before}
        hunk = re.search(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", candidate["text"])
        start = int(hunk[1]) if hunk else 1
        end = start + (int(hunk[2]) if hunk and hunk[2] else 1)
        claims = [
            claim
            for claim in current
            if key(claim) not in old
            and any(ref["line"] < end and ref["line"] + ref["quote"].count("\n") >= start for ref in claim["evidence"])
        ]
        selected = self.spec["source_invariants"].get(source["id"], self.selected(artifact_classes)) + [
            claim["invariant_id"] for claim in claims
        ]
        return platforms.evaluate(self, self.local(), claims, selected, candidate["text"])
