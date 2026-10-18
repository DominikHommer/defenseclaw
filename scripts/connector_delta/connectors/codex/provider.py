# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Codex bindings and bounded source/schema extraction; no upstream code runs."""

from __future__ import annotations

import json
import math
import re

from scripts.connector_delta import invariants as engine
from scripts.connector_delta import platforms
from scripts.connector_delta.provider import CONFIG, CommandHookProvider, _block, _mask_go


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


RUST_TEST_GUARD = r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]"


def rust_test_spans(text, include_conditional=False):
    """Balanced test-only regions; optionally exclude other conditional items.

    Other cfg/cfg_attr predicates are not evaluated or called test-only. Their
    declarations cannot supply unconditional facts, but unrelated code can.
    Malformed guards or unknown item boundaries leave the source uncertain.
    """
    masked = rust_mask(text)
    closing = {"}": "{", ")": "(", "]": "["}
    attached_attribute = re.compile(r"\s*#\s*\[")
    declaration = re.compile(
        r"\s*(?:pub(?:\([^)]*\))?\s+)?(?:(?:async|unsafe|const)\s+)*"
        r"(?P<kind>mod|fn|use|const|static|type|struct|enum|impl|trait|union)\b"
    )

    def balanced_end(start):
        stack = []
        for end in range(start, len(masked)):
            char = masked[end]
            if char in "{([":
                stack.append(char)
            elif char in closing:
                if not stack or stack.pop() != closing[char]:
                    return None
                if not stack:
                    return end + 1
        return None

    spans, covered_end = [], 0
    for attribute in re.finditer(r"#\s*(?P<inner>!?)\s*\[\s*cfg(?:_attr)?\b", masked):
        if attribute.start() < covered_end:
            continue
        if attribute["inner"]:
            return None  # Inner guards apply to an enclosing scope, not the next item.
        position, test_only = attribute.start(), False
        while attached := attached_attribute.match(masked, position):
            end = balanced_end(attached.end() - 1)
            if end is None:
                return None
            test_only |= re.fullmatch(RUST_TEST_GUARD, masked[position:end].strip()) is not None
            position = end
        item = declaration.match(masked, position)
        if item is None:
            return None
        block_item = item["kind"] in {"mod", "fn", "struct", "enum", "impl", "trait", "union"}
        stack, start = [], item.end()
        for end in range(start, min(len(masked), start + 16000)):
            char = masked[end]
            if char == ";" and not stack:
                covered_end = end + 1
                break
            if char == "{" and not stack and block_item:
                covered_end = balanced_end(end)
                if covered_end is None:
                    return None
                break
            if char in "{([":
                stack.append(char)
            elif char in closing:
                if not stack or stack.pop() != closing[char]:
                    return None
            elif char == "<" and block_item and (not stack or stack[-1] == "<"):
                stack.append(char)  # Do not mistake a const-generic brace for an item body.
            elif char == ">" and stack and stack[-1] == "<" and masked[end - 1] != "-":
                stack.pop()
            elif char == "#" and not stack:
                return None
        else:
            return None
        if test_only or include_conditional:
            spans.append((attribute.start(), covered_end))
    return spans


def rust_production_mask(text, comments_only=False):
    """Keep offsets while excluding tests; unsupported guards establish no facts."""
    spans = rust_test_spans(text, include_conditional=True)
    if spans is None:
        return None
    result = list(rust_mask(text, comments_only=comments_only))
    for start, end in spans:
        for index in range(start, end):
            if result[index] != "\n":
                result[index] = " "
    return "".join(result)


def rust_body(text, marker):
    """One uniquely identified code block; comments/strings cannot provide it."""
    masked = rust_production_mask(text)
    if masked is None:
        return None
    matches = list(re.finditer(marker, masked))
    if len(matches) != 1:
        return None
    start = opening = matches[0].end() - 1
    depth = 0
    for end in range(opening, min(len(masked), opening + 16000)):
        depth += (masked[end] == "{") - (masked[end] == "}")
        if depth == 0:
            return start + 1, end
    return None


def test_only_hunk(candidate, source, previous):
    if previous is None:
        return False
    hunk = re.fullmatch(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@[^\n]*\n([\s\S]*)", candidate["text"])
    if hunk is None:
        return False
    guards = [match.span() for match in re.finditer(RUST_TEST_GUARD, rust_mask(previous["text"]))]
    sides = []
    for row, line in ((previous, int(hunk[1])), (source, int(hunk[2]))):
        spans = rust_test_spans(row["text"])
        if spans is None:
            return False
        lines = row["text"].splitlines(keepends=True)
        offsets, position = [], 0
        for value in lines:
            offsets.append(position)
            position += len(value)
        sides.append([spans, lines, offsets, line - 1])
    changed = False
    for line in hunk[3].splitlines():
        if not line or line[0] not in {" ", "+", "-"}:
            return False
        for index in (0, 1) if line[0] == " " else (0,) if line[0] == "-" else (1,):
            spans, lines, offsets, number = sides[index]
            if not 0 <= number < len(lines) or lines[number].rstrip("\n") != line[1:]:
                return False
            if line[0] != " ":
                if line[0] == "-" and any(
                    low < offsets[number] + len(lines[number]) and offsets[number] < high for low, high in guards
                ):
                    return False  # Removing even a formatted guard can activate unchanged test code.
                changed = True
                value = lines[number].rstrip("\n")
                start = offsets[number] + len(value) - len(value.lstrip())
                end = max(start, offsets[number] + len(value.rstrip()))
                if not any(low <= start <= end <= high for low, high in spans):
                    return False
            sides[index][3] += 1
    return changed


def session_routes(text):
    span = rust_body(text, r"\blet session_start_source\s*=\s*match &initial_history\s*\{")
    if span is None:
        return [], None
    body = rust_mask(text, comments_only=True)[slice(*span)]
    variant = r"InitialHistory::[A-Za-z]+(?:\(_\))?"
    value = r"codex_hooks::SessionStartSource::([A-Za-z]+)"
    arm = re.compile(
        rf"\s*({variant}(?:\s*\|\s*{variant})*)(?:\s+if\s+(forked_from_id\.is_some\(\)))?\s*=>\s*"
        rf"(?:\{{\s*{value}\s*\}}|{value})\s*,?"
    )
    rows, position = [], 0
    while body[position:].strip():
        match = arm.match(body, position)
        if match is None or len(rows) >= 32:
            return [], None
        for selector in re.findall(variant, match[1]):
            rows.append((selector.removesuffix("(_)").split("::")[1], match[2] or "", match[3] or match[4]))
        position = match.end()
    return rows, span


def source_matcher_map(text):
    span = rust_body(text, r"\bimpl SessionStartSource\s*\{")
    if span is None:
        return {}, None
    body = rust_mask(text, comments_only=True)[slice(*span)]
    # Verify how the source is handed to matcher selection, not just an enum.
    wiring = rust_body(text, r"\bfn matcher_input\(&self\)\s*->\s*&str\s*\{")
    if wiring is None or not re.fullmatch(
        r"\s*match self\s*\{\s*Self::SessionStart\s*\{\s*source\s*\}\s*=>\s*source\.as_str\(\),\s*"
        r"Self::SubagentStart\s*\{\s*agent_type,\s*\.\.\s*\}\s*=>\s*agent_type\.as_str\(\),?\s*\}\s*",
        rust_mask(text, True)[slice(*wiring)],
    ):
        return {}, None
    declaration = re.fullmatch(
        r"\s*pub fn as_str\(self\)\s*->\s*&'static str\s*\{\s*match self\s*\{"
        r'((?:\s*Self::[A-Za-z]+\s*=>\s*"[a-z][a-z0-9_-]{0,63}"\s*,)+)\s*\}\s*\}\s*',
        body,
    )
    if declaration is None:
        return {}, None
    rows = re.findall(r'Self::([A-Za-z]+)\s*=>\s*"([a-z][a-z0-9_-]{0,63})"', body)
    if not rows or len(dict(rows)) != len(rows):
        return {}, None
    return dict(rows), (min(span[0], wiring[0]), max(span[1], wiring[1]))


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


def schema_document(text):
    """Strict, size/depth-bounded JSON; duplicate keys cannot manufacture proof."""
    if len(text) > 4 * 1024 * 1024:
        raise engine.InvariantError("schema exceeds size limit")
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > 64:
                raise engine.InvariantError("schema exceeds depth limit")
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise engine.InvariantError("unbalanced schema")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise engine.InvariantError("duplicate schema key")
            result[key] = value
        return result

    def nonfinite(_):
        raise engine.InvariantError("nonfinite schema number")

    def number(value):
        if len(value) > 128:
            raise engine.InvariantError("schema number exceeds limit")
        parsed = float(value) if any(char in value for char in ".eE") else int(value)
        if isinstance(parsed, float) and not math.isfinite(parsed):
            raise engine.InvariantError("nonfinite schema number")
        return parsed

    return json.loads(text, object_pairs_hook=unique, parse_constant=nonfinite, parse_float=number, parse_int=number)


def schema_added_fields(document, before):
    """Only top-level optional property additions; no ignored root constraints."""
    allowed = {
        "$schema",
        "title",
        "description",
        "type",
        "properties",
        "required",
        "additionalProperties",
        "definitions",
        "$defs",
    }
    if any(
        not isinstance(row, dict)
        or row.get("type") != "object"
        or set(row) - allowed
        or not isinstance(row.get("properties"), dict)
        for row in (document, before)
    ):
        return []
    added = sorted(set(document["properties"]) - set(before["properties"]))
    if not 0 < len(added) <= 128:
        return []
    required = document.get("required", [])
    if (
        not isinstance(required, list)
        or any(not isinstance(field, str) for field in required)
        or set(added) & set(required)
    ):
        return []
    reduced = {
        **document,
        "properties": {key: value for key, value in document["properties"].items() if key not in added},
    }
    # JSON equality must distinguish true/1 and other Python-equal values.
    if json.dumps(reduced, sort_keys=True) != json.dumps(before, sort_keys=True):
        return []
    return added


def schema_accepts_decision(node, value):
    """Bounded primitive response constraints, not general JSON Schema execution."""
    if node is False:
        return False
    annotations = {"title", "description", "default", "examples", "$comment", "deprecated", "readOnly", "writeOnly"}
    if not isinstance(node, dict) or set(node) - annotations - {"type", "enum", "const"}:
        return None
    types = node.get("type", [])
    types = [types] if isinstance(types, str) else types
    if (
        not isinstance(types, list)
        or len(types) > 7
        or any(
            not isinstance(item, str)
            or item not in {"string", "boolean", "number", "integer", "null", "object", "array"}
            for item in types
        )
    ):
        return None
    if types and ("boolean" if type(value) is bool else "string") not in types:
        return False
    if "const" in node and not (type(node["const"]) is type(value) and node["const"] == value):
        return False
    if "enum" in node:
        choices = node["enum"]
        if not isinstance(choices, list) or not 0 < len(choices) <= 512:
            return None
        if not any(type(item) is type(value) and item == value for item in choices):
            return False
    if "const" in node or "enum" in node or type(value) is bool and "boolean" in types:
        return True
    return None  # An unconstrained string alone is not an event-specific deny contract.


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
                if set(node) - {"$ref", "title", "description", "default", "examples", "$comment"}:
                    return None, pointer
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
                if set(node) - {"allOf", "title", "description", "default", "examples", "$comment"}:
                    return None, pointer
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
    def platform_bindings(self, common):
        from .platforms import profiles

        return profiles(self, common)

    def __init__(self, root, binding_path=CONFIG / "connectors/codex/bindings.json"):
        super().__init__(root, binding_path, "codex")

    def scope_delta(self, candidate, source, previous):
        if previous is None or not source["url"].endswith(".rs"):
            return None
        if test_only_hunk(candidate, source, previous):
            return (
                "Every edited line is inside recognized cfg(test) blocks at its pinned revision. "
                "Test evidence is retained; this does not establish runtime compatibility."
            )
        if source["id"] != "codex-hook-config":
            return None
        # Exact, narrowly documented metadata extension of HooksFile, not an
        # inference that arbitrary optional fields cannot change runtime policy.
        text = source["text"]
        span = rust_body(text, r"\bpub struct HooksFile\s*\{")
        if span is None:
            return None
        pattern = re.compile(
            r'(?m)^    #\[serde\(default, skip_serializing_if = "Option::is_none"\)\]\n'
            r"    pub description: Option<String>,\n"
        )
        additions = list(pattern.finditer(text, *span))
        binding = self.local()["hook.registration"]
        if (
            len(additions) == 1
            and text[: additions[0].start()] + text[additions[0].end() :] == previous["text"]
            and binding["verified"]
            and binding["scope"] == "local-user-inline"
        ):
            return (
                "Only optional hooks.json description metadata was added; the verified local writer uses "
                "inline TOML hooks. This scoped observation is not a runtime compatibility certificate."
            )
        return None

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
        matchers = {}
        if group_block:
            matchers = dict(re.findall(r'\{"([A-Za-z]+)",\s*"([^"\n]*)",\s*\d+\}', group_block[1]))
        selection = _block(registration, "codexHookGroupsForSetup")
        if contract["contract_id"] in {"codex-hooks-v3", "codex-hooks-v3-generic", "codex-hooks-v4"}:
            selection_text = registration[slice(*selection)] if selection else ""
            branch = re.search(r'if\s+eventType == "SessionStart"\s*&&\s*\(([^{};]+)\)\s*\{([^{}]+)\}', selection_text)
            conditions = re.findall(r'contract\.ContractID == "([a-z0-9-]+)"', branch[1]) if branch else []
            expected = {"codex-hooks-v3", "codex-hooks-v3-generic", "codex-hooks-v4"}
            clean_body = re.sub(r"//[^\n]*|/\*[\s\S]*?\*/", "", branch[2]) if branch else ""
            override = re.fullmatch(r'\s*group\.matcher = "([^"\n]*)"\s*', clean_body)
            remainder = re.sub(r'contract\.ContractID == "[a-z0-9-]+"|\|\||\s', "", branch[1]) if branch else "?"
            if (
                override
                and set(conditions) == expected
                and not remainder
                and selection_text.count("group.matcher =") == 1
            ):
                matchers["SessionStart"] = override[1]
                group_refs.append(self._ref("registration", selection))
            else:
                matchers.pop("SessionStart", None)
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
        responses, decision_tags_verified = {}, True
        for i, case in enumerate(cases):
            body = response[case.end() : cases[i + 1].start() if i + 1 < len(cases) else len(response)]
            body = _mask_go(body, comments_only=True)
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
                    emitted = dict(mapping)
                    if event in {"PreToolUse", "PermissionRequest"}:
                        masked_body = _mask_go(body)
                        tags = [
                            match[2]
                            for match in re.finditer(r'"hookEventName"(\s*:\s*)"([A-Za-z]+)"', body)
                            if masked_body[match.start(1) + match[1].index(":")] == ":"
                        ]
                        if len(tags) == 1:
                            emitted["hookSpecificOutput.hookEventName"] = tags[0]
                        else:
                            decision_tags_verified = False
                    responses[event] = emitted
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
                "hook.event_delivery",
                {"events": events, "matchers": matchers},
                [registry_ref, *group_refs],
                set(events) <= set(groups),
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
                bool(responses)
                and decision_tags_verified
                and set(responses) == set(contract["capabilities"]["block_events"]),
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

        if source["id"] in {"codex-session-init", "codex-session-start"} and previous:
            old_init = getattr(self, "upstream_before", {}).get("codex-session-init", {})
            new_init = getattr(self, "upstream_current", {}).get("codex-session-init", {})
            if old_init.get("revision") != previous["revision"] or new_init.get("revision") != source["revision"]:
                return []
            old_routes, old_span = session_routes(old_init["text"])
            new_routes, new_span = session_routes(new_init["text"])
            maps = []
            for index, transition in (
                (getattr(self, "upstream_before", {}), previous),
                (getattr(self, "upstream_current", {}), source),
            ):
                other = index.get("codex-session-start", {})
                if other.get("revision") != transition["revision"]:
                    return []  # Never combine facts from different upstream versions.
                mapping, span = source_matcher_map(other["text"])
                if not mapping:
                    return []
                self.texts[(other["url"], other["revision"])] = other["text"]
                maps.append((mapping, other, span))
            if not old_routes or not new_routes:
                return []
            for row in (old_init, new_init):
                self.texts[(row["url"], row["revision"])] = row["text"]
            for selector, guard, new_value in new_routes:
                old_value = next(
                    (
                        value
                        for variant, condition, value in old_routes
                        if variant == selector and condition in {"", guard}
                    ),
                    None,
                )
                before_value, after_value = maps[0][0].get(old_value), maps[1][0].get(new_value)
                if before_value is None or after_value is None or before_value == after_value:
                    continue
                refs = []
                for row, span in (
                    (old_init, old_span),
                    (new_init, new_span),
                    (maps[0][1], maps[0][2]),
                    (maps[1][1], maps[1][2]),
                ):
                    refs.append(
                        engine.evidence(
                            row["text"],
                            *span,
                            artifact=row["url"],
                            revision=row["revision"],
                            role="upstream",
                            authority="source_assignment",
                        )
                    )
                claims.append(
                    {
                        "invariant_id": "hook.event_delivery",
                        "kind": "event_selector_transition",
                        "value": {
                            "before": before_value,
                            "after": after_value,
                            "scenario": selector + (" if " + guard if guard else " (fallback)"),
                        },
                        "event": "SessionStart",
                        "field": "source",
                        "authority": "source_assignment",
                        "evidence": refs,
                    }
                )
            return claims

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
            document = schema_document(text)
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
                        value = "number" if value == "integer" else value
                        if value in {"string", "number", "boolean", "object", "array", "null"}:
                            add("hook.payload", "field_type", value, span[1:], event=event, field=field)
                            if field == "tool_use_id":
                                add("hook.correlation", "field_type", value, span[1:], event=event, field=field)
                before = schema_document(previous["text"]) if previous else {}
                before = before if isinstance(before, dict) else {}
                added = schema_added_fields(document, before)
                if (
                    added
                    and previous
                    and event in self.local()["hook.correlation"]["values"]["events"]
                    and previous["revision"] != revision
                    and max(len(text), len(previous["text"])) <= 24000
                ):
                    self.texts[(previous["url"], previous["revision"])] = previous["text"]
                    refs = [
                        engine.evidence(
                            row["text"],
                            0,
                            len(row["text"]),
                            artifact=row["url"],
                            revision=row["revision"],
                            role="upstream",
                            authority="declared_schema",
                        )
                        for row in (previous, source)
                    ]
                    claims.append(
                        {
                            "invariant_id": "hook.correlation",
                            "kind": "fields_added",
                            "value": added,
                            "event": event,
                            "authority": "declared_schema",
                            "evidence": refs,
                        }
                    )
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
                    accepted = schema_accepts_decision(node, value)
                    if accepted is not None:
                        add(
                            "hook.decision",
                            "decision_accepted" if accepted else "decision_rejected",
                            value,
                            span[1:],
                            event=event,
                            field=field,
                        )
            return claims
        # Mask only recognized test regions, preserving original evidence offsets.
        # Strings cannot supply guards; unknown syntax cannot establish production.
        code = rust_production_mask(text, comments_only=True)
        if code is None:
            return claims
        if source["id"] == "codex-home-discovery":
            default = re.search(
                r"None => \{\s*let mut p = home_dir\(\)\.ok_or_else\(\|\| \{[\s\S]*?\}\)\?;"
                r'\s*p\.push\("([^"/]+)"\);\s*AbsolutePathBuf::from_absolute_path\(p\)\s*\}',
                code,
            )
            if default:
                add("hook.discovery", "default_directory", "~/" + default[1], default.span())
        elif source["id"] == "codex-hook-config":
            old_code = rust_production_mask(previous["text"], comments_only=True) if previous else None
            event_block = re.search(r"pub struct HookEventsToml\s*\{([\s\S]*?)\n\}", code)
            if event_block:
                events = re.findall(r'#\[serde\(rename = "([A-Za-z]+)", default\)\]', event_block[1])
                if events:
                    add("hook.event_delivery", "event_inventory", events, event_block.span())
                    # Unlike a doc inventory, this is the typed config plus its
                    # exhaustive event-to-group dispatch. Require both before
                    # calling an absent old event a removal, and reject aliases.
                    dispatch = re.search(r"pub fn matcher_groups_mut\b([\s\S]*?)\n    \}", code)
                    old_block = re.search(r"pub struct HookEventsToml\s*\{([\s\S]*?)\n\}", old_code or "")
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
                if handlers and 'rename = "command"' in (old_code or "") and "alias" not in handlers[1]:
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

        old = {key(claim): [ref["quote"] for ref in claim["evidence"]] for claim in before}
        hunk = re.search(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", candidate["text"])
        start = int(hunk[1]) if hunk else 1
        end = start + (int(hunk[2]) if hunk and hunk[2] else 1)
        claims = [
            claim
            for claim in current
            if (
                key(claim) not in old
                or claim["kind"] == "decision_accepted"
                and source["url"].endswith(".command.output.schema.json")
                and old[key(claim)] != [ref["quote"] for ref in claim["evidence"]]
            )
            and any(
                ref["artifact"] == source["url"]
                and ref["revision"] == source["revision"]
                and ref["line"] < end
                and ref["line"] + ref["quote"].count("\n") >= start
                for ref in claim["evidence"]
            )
        ]
        selected = self.spec["source_invariants"].get(source["id"], self.selected(artifact_classes)) + [
            claim["invariant_id"] for claim in claims
        ]
        return platforms.evaluate(self, self.local(), claims, selected, candidate["text"])
