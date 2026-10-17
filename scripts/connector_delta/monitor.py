#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0

"""Read-only upstream -> DefenseClaw impact monitor. Python stdlib only.

collect retrieves public, allowlisted text; analyze compares snapshots; backtest
replays release notes against the CURRENT checkout, not historical local code.
No agent binaries, gateway, installation, issue writes or generated code run.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import difflib
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Use only this checkout's trusted provider code; never import downloaded code.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts.connector_delta import invariants as invariant_engine  # noqa: E402
from scripts.connector_delta.connectors import PROVIDERS  # noqa: E402

CONFIG = Path(__file__).resolve().parent
MAX_BYTES = 4 * 1024 * 1024
MAX_CHANGE = 24000
MAX_CONTEXT = 100000
SCHEMA = 1
CODEX_PATHS = {row["path"] for row in json.loads((CONFIG / "connectors/codex/manifest.json").read_text())["sources"]}
VERSION = re.compile(r"^## (\d+\.\d+\.\d+)\s*$", re.MULTILINE)
DECISIONS = {"no_impact", "observed", "review_required", "validation_required"}
IMPACTS = {"none", "low", "medium", "high", "critical", "unknown"}
KINDS = {"additive", "behavior_change", "breaking", "bugfix", "unknown"}
ANCHORS = {
    "hook_events": ["newClaudeCodeHookGroup", "codexHookGroups", "case ", "HookEventName"],
    "response_semantics": ["permissionDecision", "updatedInput", "claudeCodeOutput", "codexOutput", "exit 2"],
    "runtime_behavior": ["Timeout", "timeout", "async", "max-time", "fail_unreachable"],
    "config_discovery": [
        "allowManagedHooksOnly",
        "disableAllHooks",
        "CLAUDE_CONFIG_DIR",
        "CODEX_HOME",
        "codexCommandHookHash",
        "trusted_hash",
        "precedence",
    ],
    "input_correlation": ["tool_use_id", "ToolUseID", "ToolName", "SessionID", "json:"],
    "telemetry": ["claudecode", "tool_decision", "OTEL_", "correlation"],
    "plugin_inventory": ["defaultEnabled", "enabledPlugins", "plugin.json", "claude"],
    "unclassified_hook_change": ["hookGroups", "newClaudeCodeHookGroup"],
}


class MonitorError(ValueError):
    """A collection, grounding, configuration or state error, never 'safe'."""


def digest(value):
    if not isinstance(value, str):
        value = json.dumps(value, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(value.encode()).hexdigest()


def read_text(path, limit=MAX_BYTES):
    with Path(path).open("rb") as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise MonitorError("input exceeds configured byte limit")
    return content.decode("utf-8")


def load_json(path):
    return json.loads(read_text(path, limit=32 * 1024 * 1024))


def write_text(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_json(path, value):
    write_text(path, json.dumps(value, indent=2, ensure_ascii=True) + "\n")


def normalize(text):
    return "\n".join(line.rstrip() for line in text.replace("\r\n", "\n").splitlines()).strip() + "\n"


def version_tuple(version):
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise MonitorError("versions must be exact x.y.z values")
    return tuple(map(int, version.split(".")))


def checked_url(url, *, model=False):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port or parsed.fragment:
        raise MonitorError("refusing noncanonical HTTPS URL")
    if model:
        allowed = url == "https://api.anthropic.com/v1/messages"
    else:
        codex_raw = re.fullmatch(r"/openai/codex/([a-f0-9]{40})/(.+)", parsed.path)
        allowed = (
            (parsed.netloc == "api.github.com" and parsed.path == "/repos/anthropics/claude-code/commits/main")
            or (
                parsed.netloc == "raw.githubusercontent.com"
                and re.fullmatch(r"/anthropics/claude-code/[a-f0-9]{40}/CHANGELOG\.md", parsed.path)
            )
            or (parsed.netloc == "code.claude.com" and parsed.path in {"/docs/en/hooks.md", "/docs/en/settings.md"})
            or (parsed.netloc == "api.github.com" and parsed.path == "/repos/openai/codex/commits/main")
            or (parsed.netloc == "raw.githubusercontent.com" and codex_raw and codex_raw[2] in CODEX_PATHS)
        ) and not parsed.query
        if parsed.netloc == "api.github.com" and parsed.path == "/repos/openai/codex/commits":
            try:
                query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
            except ValueError:
                raise MonitorError("malformed history URL query") from None
            allowed = (
                set(query) == {"sha", "path", "per_page"}
                and query["sha"] == ["main"]
                and query["path"] in [["codex-rs/hooks"], ["codex-rs/config/src/hook_config.rs"]]
                and len(query["per_page"]) == 1
                and query["per_page"][0].isdigit()
                and 1 <= int(query["per_page"][0]) <= 30
            )
    inventory_path = re.fullmatch(
        r"/repos/(openai/codex|anthropics/claude-code)/pulls(?:/([1-9]\d*)/files)?", parsed.path
    )
    if not model and parsed.netloc == "api.github.com" and inventory_path:
        try:
            query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
        except ValueError:
            raise MonitorError("malformed inventory query") from None
        common = query.get("per_page") == ["100"] and len(query.get("page", [])) == 1
        page = query.get("page", [""])[0]
        allowed = bool(common and page.isdigit() and 1 <= int(page) <= (10 if inventory_path[2] else 3))
        allowed = allowed and (
            set(query) == {"per_page", "page"}
            if inventory_path[2]
            else set(query) == {"state", "base", "sort", "direction", "per_page", "page"}
            and query["state"] == ["closed"]
            and query["base"] == ["main"]
            and query["sort"] == ["updated"]
            and query["direction"] == ["desc"]
        )
    if not allowed:
        raise MonitorError("URL is outside the fixed source allowlist")
    return url


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # In particular, never forward API credentials across redirects.
        return None


def request_text(url, *, payload=None, headers=None, model=False):
    checked_url(url, model=model)
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "User-Agent": "DefenseClaw-Connector-Delta-Monitor/1",
            **(headers or {}),
        },
    )
    try:
        opener = urllib.request.build_opener(NoRedirect())
        with opener.open(req, timeout=60 if model else 25) as response:
            if response.status != 200:
                raise MonitorError("unexpected upstream HTTP status")
            content = response.read(MAX_BYTES + 1)
        if len(content) > MAX_BYTES:
            raise MonitorError("upstream response exceeds 4 MiB")
        return content.decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise MonitorError(f"HTTP {exc.code} from {urllib.parse.urlsplit(url).netloc}") from None
    except (urllib.error.URLError, TimeoutError, OSError, UnicodeError):
        # Error bodies/headers may contain credentials. Never log them.
        raise MonitorError(f"transport/encoding failure from {urllib.parse.urlsplit(url).netloc}") from None


def load_manifest(path=CONFIG / "connectors/claudecode/manifest.json", root=ROOT):
    manifest = load_json(path)
    if manifest.get("schema_version") != SCHEMA or manifest.get("connector") not in PROVIDERS:
        raise MonitorError("unsupported manifest")
    for rule in manifest["rules"]:
        for pattern in rule["patterns"]:
            re.compile(pattern, re.IGNORECASE)
        for relative in rule["consumers"]:
            safe_local(root, relative)
    return manifest


def safe_local(root, relative):
    root = Path(root).resolve()
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise MonitorError(f"missing or out-of-repository consumer: {relative}")
    return path


def collect(manifest, fetch=request_text, revision_override=None, *, include_inventory=False, inventory_state=None):
    snapshot = {"schema_version": SCHEMA, "connector": manifest["connector"], "sources": [], "errors": []}
    revision = revision_override
    for spec in manifest["sources"]:
        try:
            url = spec["url"]
            if "{revision}" in url:
                if not revision:
                    headers = {"Accept": "application/vnd.github+json"}
                    token = os.environ.get("GH_TOKEN", "")
                    if token:
                        headers["Authorization"] = f"Bearer {token}"
                    metadata = json.loads(
                        fetch(
                            "https://api.github.com/repos/"
                            + manifest.get("upstream_repository", "anthropics/claude-code")
                            + "/commits/main",
                            headers=headers,
                        )
                    )
                    revision = metadata["sha"]
                if not re.fullmatch(r"[a-f0-9]{40}", revision):
                    raise MonitorError("invalid upstream commit SHA")
                url = url.format(revision=revision)
            checked_url(url)
            text = normalize(fetch(url))
            if not text.strip() or text.lstrip().startswith(("<!DOCTYPE", "<html")):
                raise MonitorError("expected nonempty Markdown, not an HTML error page")
            if spec["kind"] == "changelog" and not VERSION.search(text):
                raise MonitorError("changelog has no recognized releases")
            snapshot["sources"].append(
                {
                    "id": spec["id"],
                    "kind": spec["kind"],
                    "url": url,
                    "revision": revision if "{revision}" in spec["url"] else digest(text),
                    "content_sha256": digest(text),
                    "text": text,
                }
            )
        except (MonitorError, KeyError, TypeError, json.JSONDecodeError) as exc:
            snapshot["errors"].append({"source": spec["id"], "reason": str(exc)[:200]})
    if include_inventory:
        from scripts.connector_delta import inventory

        try:
            snapshot["pr_inventory"] = inventory.collect(manifest, fetch, inventory_state)
        except (MonitorError, ValueError, KeyError, TypeError) as exc:
            snapshot["pr_inventory"] = {
                "repository": inventory.REPOSITORIES[manifest["connector"]],
                "prs": [],
                "errors": ["PR inventory collection failed; coverage is incomplete"],
            }
            snapshot["errors"].append({"source": "upstream-pr-inventory", "reason": str(exc)[:200]})
    return snapshot


def releases(text):
    headings = list(VERSION.finditer(text))
    result = []
    for i, heading in enumerate(headings):
        start = heading.end()
        end = headings[i + 1].start() if i + 1 < len(headings) else len(text)
        body = text[start:end]
        offset = text[:start].count("\n") + 1
        bullet = []
        line_number = offset
        for index, line in enumerate(body.splitlines() + ["- __end__"]):
            if line.startswith("- "):
                if bullet:
                    result.append({"version": heading[1], "text": "\n".join(bullet).strip(), "line": line_number})
                bullet = [line]
                line_number = offset + index
            elif bullet:
                bullet.append(line)
    return result


def candidates(source, previous=None, *, lookback=20, lower=None, upper=None):
    if source["kind"] in {"document", "source"}:
        if previous is None:
            return []  # First fetch is an explicit baseline, never a clean bill of health.
        diff = list(
            difflib.unified_diff(
                previous["text"].splitlines(),
                source["text"].splitlines(),
                n=3,
                fromfile="previous",
                tofile="current",
                lineterm="",
            )
        )
        hunks, hunk = [], []
        for line in diff[2:]:
            if line.startswith("@@") and hunk:
                hunks.append("\n".join(hunk))
                hunk = []
            hunk.append(line)
        if hunk:
            hunks.append("\n".join(hunk))
        return [make_candidate(source, text, "document_diff", before=previous["revision"]) for text in hunks]
    current = releases(source["text"])
    if not current:
        raise MonitorError("changelog has no recognized release bullets")
    if previous is None:
        versions = sorted({row["version"] for row in current}, key=version_tuple, reverse=True)
        selected = set(versions[:lookback] if lookback else versions)
        rows = [(row, "release_note") for row in current if row["version"] in selected]
    else:
        before = releases(previous["text"])
        before_ids = {(row["version"], row["text"]) for row in before}
        after_ids = {(row["version"], row["text"]) for row in current}
        rows = [(row, "release_note") for row in current if (row["version"], row["text"]) not in before_ids]
        rows += [(row, "removed_release_note") for row in before if (row["version"], row["text"]) not in after_ids]
    result = []
    for row, kind in rows:
        version = version_tuple(row["version"])
        if (lower and version < version_tuple(lower)) or (upper and version > version_tuple(upper)):
            continue
        result.append(make_candidate(source, row["text"], kind, version=row["version"], line=row["line"]))
    return result


def make_candidate(source, text, kind, **extra):
    return {
        "id": digest([source["id"], kind, text, extra.get("version", ""), extra.get("before", "")]),
        "source": source["id"],
        "url": source["url"],
        "source_revision": source["revision"],
        "kind": kind,
        "text": text,
        **extra,
    }


def match_rules(candidate, manifest):
    if manifest["connector"] == "codex":
        source = next((spec for spec in manifest["sources"] if spec["id"] == candidate["source"]), None)
        return [rule for rule in manifest["rules"] if source and rule["id"] in source["artifact_classes"]]
    # Match only edited lines for docs; unchanged context must not create a match.
    text = candidate["text"]
    if candidate["kind"] == "document_diff":
        text = "\n".join(line[1:] for line in text.splitlines() if line.startswith(("+", "-")))
    matches, fallback = [], []
    for rule in manifest["rules"]:
        if any(re.search(pattern, text, re.IGNORECASE) for pattern in rule["patterns"]):
            (fallback if rule.get("fallback") else matches).append(rule)
    return matches or fallback


def local_context(candidate, matches, root, checks=None, connector="claudecode"):
    if checks is None:
        provider = PROVIDERS[connector](root)
        checks = invariant_engine.evaluate(
            provider.catalog,
            provider.local(candidate.get("version")),
            [],
            selected=provider.selected([rule["id"] for rule in matches]),
            transport=provider.transport,
            texts=provider.texts,
        )
    unresolved = [check for check in checks if check["verdict"] == "review_required"]
    symbols = re.findall(r"`([A-Za-z_][A-Za-z_0-9.]{2,70})`|\b([A-Z][a-z]+(?:[A-Z][a-z]+)+)\b", candidate["text"])
    exact = list(dict.fromkeys(a or b for a, b in symbols))[:12]
    artifacts = []
    for relative in dict.fromkeys(path for rule in matches for path in rule["consumers"]):
        lines = read_text(safe_local(root, relative)).splitlines()
        preferred = [i for i, line in enumerate(lines) if any(word in line for word in exact)]
        anchors = [word for rule in matches if relative in rule["consumers"] for word in ANCHORS[rule["id"]]]
        hits = preferred + [i for i, line in enumerate(lines) if any(word in line for word in anchors)]
        indexes = set()
        for hit in list(dict.fromkeys(hits))[:16] or [min(25, len(lines) - 1)]:
            indexes.update(range(max(0, hit - 4), min(len(lines), hit + 7)))
        chosen = sorted(indexes)[:160]
        artifacts.append(
            {
                "path": relative,
                "lines": [{"number": i + 1, "text": lines[i]} for i in chosen],
                "excerpt": len(chosen) < len(lines),
            }
        )
    contracts = load_json(safe_local(root, "cli/defenseclaw/inventory/hook_contracts.json"))["connectors"][connector]
    packet = {
        "direction": "upstream -> current DefenseClaw",
        "connector": connector,
        "upstream": candidate,
        "artifact_classes": [rule["id"] for rule in matches],
        "invariants": [
            {
                **{key: check[key] for key in ("invariant_id", "scope", "verdict", "reason", "local_values")},
                "local_evidence_ranges": [
                    {
                        "path": ref["artifact"],
                        "revision": ref["revision"],
                        "start_line": ref["line"],
                        "end_line": ref["line"] + ref["quote"].count("\n"),
                    }
                    for ref in check["local_evidence"]
                ],
            }
            for check in unresolved
        ],
        "questions": [
            f"For {check['invariant_id']} in scope {check['scope']}, does this delta contradict "
            f"the supplied local binding? Identify the exact changed value and consumed value; "
            f"otherwise state the missing evidence. {check['reason']}"
            for check in unresolved
        ],
        "contract_ids": [row["contract_id"] for row in contracts["contracts"]],
        "local_artifacts": artifacts,
        "recommended_tests": sorted({command for rule in matches for command in rule["tests"]}),
    }
    # Include precise binding evidence even when keyword excerpts missed it.
    # Limit each invariant to bounded numbered lines; incomplete context stays
    # explicit and is not grounds for a compatibility claim.
    by_path = {artifact["path"]: artifact for artifact in packet["local_artifacts"]}
    original_lines = {}
    for check in unresolved:
        for ref in check["local_evidence"]:
            if ref["artifact"] not in original_lines:
                original_lines[ref["artifact"]] = read_text(safe_local(root, ref["artifact"])).splitlines()
            artifact = by_path.setdefault(ref["artifact"], {"path": ref["artifact"], "lines": [], "excerpt": True})
            existing = {line["number"] for line in artifact["lines"]}
            for offset, line in enumerate(ref["quote"].splitlines()[:90]):
                number = ref["line"] + offset
                if number not in existing and len(artifact["lines"]) < 220:
                    # A span can start mid-line; cite the original full line.
                    original = original_lines[ref["artifact"]][number - 1]
                    artifact["lines"].append({"number": number, "text": original})
                    existing.add(number)
    packet["local_artifacts"] = list(by_path.values())
    if len(json.dumps(packet)) > MAX_CONTEXT:
        raise MonitorError("selected context exceeds 100k character budget; narrow the manifest")
    return packet


def validate_analysis(value, packet):
    keys = {
        "decision",
        "impact",
        "change_kind",
        "summary",
        "comparisons",
        "recommended_tests",
        "unknowns",
        "invariant_ids",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise MonitorError("model output does not match the finding schema")
    ids = value["invariant_ids"]
    supplied = {check["invariant_id"] for check in packet["invariants"]}
    if (
        not isinstance(ids, list)
        or not ids
        or any(not isinstance(item, str) for item in ids)
        or len(ids) != len(set(ids))
        or set(ids) != supplied
    ):
        raise MonitorError("model must cover exactly the supplied unresolved invariant IDs")
    if any(not isinstance(value[key], str) for key in ("decision", "impact", "change_kind")):
        raise MonitorError("model classifications must be strings")
    if value["decision"] not in DECISIONS or value["impact"] not in IMPACTS or value["change_kind"] not in KINDS:
        raise MonitorError("model returned an unsupported classification")
    if not isinstance(value["summary"], str) or not 1 <= len(value["summary"]) <= 4000:
        raise MonitorError("model summary must be a bounded string")
    for field in ("recommended_tests", "unknowns"):
        if (
            not isinstance(value[field], list)
            or len(value[field]) > 20
            or any(not isinstance(item, str) or len(item) > 2000 for item in value[field])
        ):
            raise MonitorError(f"invalid model {field}")
    if not set(value["recommended_tests"]).issubset(packet["recommended_tests"]):
        raise MonitorError("model invented a test command")
    comparisons = value["comparisons"]
    if not isinstance(comparisons, list) or not 1 <= len(comparisons) <= 12:
        raise MonitorError("model finding requires grounded comparisons")
    lookup = {
        artifact["path"]: {line["number"]: line["text"] for line in artifact["lines"]}
        for artifact in packet["local_artifacts"]
    }
    expected = {"invariant_id", "upstream_quote", "local_artifact", "local_line", "local_quote", "assessment"}
    for comparison in comparisons:
        if not isinstance(comparison, dict) or set(comparison) != expected:
            raise MonitorError("invalid comparison schema")
        if any(
            not isinstance(comparison[key], str) or not 1 <= len(comparison[key]) <= 4000
            for key in expected - {"local_line"}
        ):
            raise MonitorError("comparison text must be nonempty and bounded")
        if comparison["invariant_id"] not in supplied:
            raise MonitorError("comparison names an invariant outside the supplied scope")
        if type(comparison["local_line"]) is not int:
            raise MonitorError("invalid citation line type")
        bound = next(check for check in packet["invariants"] if check["invariant_id"] == comparison["invariant_id"])
        if not any(
            ref["path"] == comparison["local_artifact"]
            and ref["start_line"] <= comparison["local_line"] <= ref["end_line"]
            for ref in bound["local_evidence_ranges"]
        ):
            raise MonitorError("model citation is outside the named invariant's local binding")
        line = lookup.get(comparison["local_artifact"], {}).get(comparison["local_line"], "")
        if comparison["upstream_quote"] not in packet["upstream"]["text"] or comparison["local_quote"] not in line:
            raise MonitorError("model citation does not exist in the supplied upstream/local evidence")
    if {comparison["invariant_id"] for comparison in comparisons} != supplied:
        raise MonitorError("every unresolved invariant requires its own grounded comparison")
    if value["decision"] == "no_impact" and value["impact"] != "none":
        raise MonitorError("no_impact must have impact=none")
    if value["change_kind"] == "breaking" and value["decision"] != "validation_required":
        raise MonitorError("model-suspected breaks require validation_required, never a deterministic verdict")
    return value


def anthropic_analysis(packet, model, system, fetch=request_text):
    token = os.environ.get("ANTHROPIC_API_KEY", "")
    if not token or not model:
        raise MonitorError("AI requested: ANTHROPIC_API_KEY and --model are required")
    payload = {
        "model": model,
        "max_tokens": 2400,
        "system": system,
        "messages": [{"role": "user", "content": json.dumps(packet, ensure_ascii=True)}],
    }
    raw = json.loads(
        fetch(
            "https://api.anthropic.com/v1/messages",
            model=True,
            headers={"x-api-key": token, "anthropic-version": "2023-06-01", "Content-Type": "application/json"},
            payload=json.dumps(payload).encode(),
        )
    )
    if not isinstance(raw, dict) or raw.get("stop_reason") != "end_turn":
        raise MonitorError("model output was truncated or did not complete")
    blocks = raw.get("content", [])
    if not isinstance(blocks, list) or any(
        not isinstance(block, dict) or block.get("type") != "text" for block in blocks
    ):
        raise MonitorError("model returned non-text content")
    value = json.loads("".join(block["text"] for block in blocks))
    return validate_analysis(value, packet)


def check_snapshot(snapshot, manifest):
    if not isinstance(snapshot, dict) or snapshot.get("schema_version") != SCHEMA:
        raise MonitorError("unsupported snapshot schema")
    if snapshot.get("connector", manifest["connector"]) != manifest["connector"]:
        raise MonitorError("snapshot belongs to a different connector")
    specs = {row["id"]: row for row in manifest["sources"]}
    sources = snapshot.get("sources")
    if not isinstance(sources, list) or len(sources) > len(specs):
        raise MonitorError("invalid snapshot sources")
    seen = set()
    for source in sources:
        if not isinstance(source, dict) or source.get("id") not in specs or source["id"] in seen:
            raise MonitorError("unknown or duplicate snapshot source")
        seen.add(source["id"])
        if source.get("kind") != specs[source["id"]]["kind"]:
            raise MonitorError("source kind differs from manifest")
        checked_url(source.get("url", ""))
        expected = specs[source["id"]]["url"].replace("{revision}", source.get("revision", ""))
        if source["url"] != expected:
            raise MonitorError("snapshot URL/revision differs from manifest")
        if (
            not isinstance(source.get("text"), str)
            or not source["text"].strip()
            or len(source["text"].encode()) > MAX_BYTES
        ):
            raise MonitorError("empty or oversized source text")
        if source["kind"] == "document" and digest(source["text"]) != source.get("revision"):
            raise MonitorError("document snapshot hash mismatch")
        if source["kind"] == "source" and digest(source["text"]) != source.get("content_sha256"):
            raise MonitorError("source snapshot hash mismatch")
    errors = snapshot.get("errors", [])
    if not isinstance(errors, list) or len(errors) > len(specs) + int("pr_inventory" in snapshot):
        raise MonitorError("invalid snapshot errors")
    return seen


def run_monitor(
    snapshot,
    manifest,
    state=None,
    *,
    root=ROOT,
    ai="off",
    model="",
    max_ai=10,
    lookback=20,
    lower=None,
    upper=None,
    prompts=None,
    analyzer=anthropic_analysis,
):
    seen = check_snapshot(snapshot, manifest)
    state = {"schema_version": SCHEMA, "sources": {}, "cache": {}} if state is None else state
    if (
        not isinstance(state, dict)
        or state.get("schema_version") != SCHEMA
        or not isinstance(state.get("sources"), dict)
        or not isinstance(state.get("cache"), dict)
    ):
        raise MonitorError("invalid checkpoint; refusing to silently reset history")
    # Validate persisted snapshots too: a corrupt/poisoned checkpoint is not a baseline.
    check_snapshot({"schema_version": SCHEMA, "sources": list(state["sources"].values())}, manifest)
    pending = state.setdefault("pending_sources", {})
    if not isinstance(pending, dict):
        raise MonitorError("invalid pending-source checkpoint")
    check_snapshot({"schema_version": SCHEMA, "sources": list(pending.values())}, manifest)
    system = read_text(CONFIG / "shared/system-prompt.txt")
    provider = PROVIDERS[manifest["connector"]](root)
    context_digest = digest(
        {
            path: digest(read_text(safe_local(root, path)))
            for path in sorted(
                {
                    "cli/defenseclaw/inventory/hook_contracts.json",
                    *provider.spec["local_sources"].values(),
                    *(path for rule in manifest["rules"] for path in rule["consumers"]),
                }
            )
        }
    )
    implementation_digest = digest(
        {
            path: read_text(CONFIG / path)
            for path in (
                "monitor.py",
                "invariants.py",
                "provider.py",
                "history.py",
                "connectors/__init__.py",
                "shared/invariants.json",
                "inventory.py",
                "platforms.py",
                f"connectors/{manifest['connector']}/provider.py",
                f"connectors/{manifest['connector']}/bindings.json",
            )
        }
    )
    signature = digest([manifest, system, implementation_digest, ai, model])
    reset = state.get("signature") not in (None, signature)
    if reset:
        state = {
            "schema_version": SCHEMA,
            "sources": {},
            "cache": {},
            "pending_sources": {},
            "notification_outbox": state.get("notification_outbox", []),
        }
    state["signature"] = signature
    revision = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    report = {
        "schema_version": SCHEMA,
        "connector": manifest["connector"],
        "analysis_mode": "invariants_only" if ai == "off" else "invariants+anthropic",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "defenseclaw_revision": revision,
        "context_digest": context_digest,
        "implementation_digest": implementation_digest,
        "analyzer_signature": signature,
        "baseline_reset": reset,
        "coverage": manifest.get(
            "coverage", "Public changelog and docs only; undisclosed runtime changes are not observable."
        ),
        "invariant_catalog": list(provider.catalog),
        "platform_coverage": provider.platform_coverage,
        "proof_scope": "Static contract conflicts, not verified live-client regressions.",
        "sources": [],
        "findings": [],
        "gaps": [],
    }
    for missing in sorted({row["id"] for row in manifest["sources"]} - seen):
        report["gaps"].append(
            {"source": missing, "decision": "collection_gap", "reason": "source missing; checkpoint retained"}
        )
    calls = 0
    for collected in snapshot["sources"]:
        # Finish a frozen batch before moving on to newer upstream content.
        # Otherwise a sliding initial lookback can drop unreviewed old changes
        # when the model budget is smaller than the incoming stream.
        source = state["pending_sources"].get(collected["id"], collected)
        deferred = source["text"] != collected["text"]
        previous = state["sources"].get(source["id"])
        gap_start = len(report["gaps"])
        row = {
            "id": source["id"],
            "revision": source["revision"],
            "url": source["url"],
            "collected_revision": collected["revision"],
            "newer_snapshot_deferred": deferred,
            "status": "baseline_created"
            if previous is None and source["kind"] in {"document", "source"}
            else "compared",
            "initial_release_lookback": lookback if previous is None and source["kind"] == "changelog" else None,
        }
        report["sources"].append(row)
        try:
            changes = candidates(source, previous, lookback=lookback, lower=lower, upper=upper)
        except MonitorError as exc:
            report["gaps"].append({"source": source["id"], "decision": "collection_gap", "reason": str(exc)})
            continue
        for candidate in changes:
            matches = match_rules(candidate, manifest)
            finding = {
                "candidate": candidate,
                "artifact_classes": [rule["id"] for rule in matches],
                "decision": "review_required" if matches else "filtered",
                "impact": "unknown" if matches else "none",
                "analysis_status": "not_run" if matches else "skipped",
                "risk_hints": sorted({rule["risk"] for rule in matches}),
                "local_artifacts": sorted({path for rule in matches for path in rule["consumers"]}),
                "recommended_tests": sorted({cmd for rule in matches for cmd in rule["tests"]}),
                "invariants": [],
            }
            report["findings"].append(finding)
            if len(candidate["text"]) > MAX_CHANGE:
                finding.update(decision="collection_gap", impact="unknown", analysis_status="incomplete")
                report["gaps"].append(
                    {
                        "source": source["id"],
                        "candidate": candidate["id"],
                        "decision": "collection_gap",
                        "reason": "change exceeds 24k context limit",
                    }
                )
                continue
            try:
                checks = provider.checks(candidate, source, previous, finding["artifact_classes"])
                finding["invariants"] = checks
                finding["local_artifacts"] = sorted(
                    set(finding["local_artifacts"])
                    | {ref["artifact"] for check in checks for ref in check["local_evidence"]}
                )
                if not matches and not checks:
                    continue
                broken = [check for check in checks if check["verdict"] == "breaking_change"]
                unresolved = [check for check in checks if check["verdict"] == "review_required"]
                if broken:
                    finding.update(
                        decision="breaking_change",
                        impact=max(
                            (check["impact"] for check in broken),
                            key=lambda severity: ["high", "critical"].index(severity),
                        ),
                        analysis_status="deterministic_contract_conflict",
                    )
                    continue
                if checks and not unresolved:
                    finding.update(decision="observed", impact="none", analysis_status="deterministic_comparison")
                    continue
                finding.update(decision="review_required", impact="unknown", analysis_status="evidence_insufficient")
                if not checks:
                    finding["unknowns"] = [
                        "No shared invariant binding exists yet for this artifact class; no broad AI query was sent."
                    ]
                    continue
                if any(not check["local_binding_verified"] for check in unresolved):
                    finding["unknowns"] = [
                        "Local invariant extraction is unverified; repair the binding before requesting AI inference."
                    ]
                    continue
                if ai == "off" and not prompts:
                    continue
                packet = local_context(candidate, matches, root, checks, manifest["connector"])
                packet["defenseclaw_revision"] = revision
                if prompts:
                    write_json(Path(prompts) / f"{candidate['id']}.json", {"system": system, "user": packet})
                if ai == "off":
                    continue
                cache_key = digest([candidate["id"], context_digest, signature])
                if cache_key in state["cache"]:
                    analysis = validate_analysis(state["cache"][cache_key], packet)
                    finding["analysis_status"] = "cached"
                else:
                    if calls >= max_ai:
                        raise MonitorError("AI call budget exhausted; matched candidates remain pending")
                    calls += 1
                    analysis = validate_analysis(analyzer(packet, model, system), packet)
                    state["cache"][cache_key] = analysis
                    finding["analysis_status"] = "completed"
                finding.update(analysis=analysis, decision=analysis["decision"], impact=analysis["impact"])
            except (MonitorError, invariant_engine.InvariantError, json.JSONDecodeError, TypeError, KeyError) as exc:
                if finding["decision"] != "breaking_change":
                    finding.update(decision="collection_gap", impact="unknown", analysis_status="incomplete")
                report["gaps"].append(
                    {
                        "source": source["id"],
                        "candidate": candidate["id"],
                        "decision": "collection_gap",
                        "reason": str(exc)[:200],
                    }
                )
        if len(report["gaps"]) == gap_start:
            state["sources"][source["id"]] = source
            state["pending_sources"].pop(source["id"], None)
            if deferred:
                report["gaps"].append(
                    {
                        "source": source["id"],
                        "decision": "collection_gap",
                        "reason": "frozen backlog completed; newer collected snapshot deferred until next run",
                    }
                )
        else:
            row["status"] = "checkpoint_retained"
            state["pending_sources"][source["id"]] = source
    state["cache"] = dict(list(state["cache"].items())[-5000:])
    from scripts.connector_delta import inventory

    try:
        inventory.apply(snapshot, manifest, provider, report, state)
    except (ValueError, KeyError, TypeError, invariant_engine.InvariantError):
        report["gaps"].append(
            {
                "source": "upstream-pr-inventory",
                "decision": "collection_gap",
                "reason": "Malformed or incomplete PR inventory; coverage could not be verified",
            }
        )
    report["summary"] = dict(collections.Counter(finding["decision"] for finding in report["findings"]))
    report["invariant_summary"] = dict(
        collections.Counter(check["verdict"] for finding in report["findings"] for check in finding["invariants"])
    )
    report["ai_calls"] = calls
    report["outcome"] = "incomplete" if report["gaps"] else "complete"
    return report, state


def benchmark(report, expectations):
    results = []
    for case in expectations:
        found = [
            row
            for row in report["findings"]
            if row["candidate"].get("version") == case["version"] and case["contains"] in row["candidate"]["text"]
        ]
        classes = set().union(*(set(row["artifact_classes"]) for row in found))
        expected = set(case["expected_classes"])
        passed = len(found) == 1 and (expected <= classes if expected else not classes)
        results.append({**case, "passed": passed, "matches": len(found), "actual_classes": sorted(classes)})
    return {
        "evaluation": "Curated relevance labels, not runtime breakage or historical predictive accuracy.",
        "passed": sum(row["passed"] for row in results),
        "total": len(results),
        "cases": results,
    }


def invariant_backtest(root=ROOT, fixture=None, connector="claudecode"):
    fixture = fixture or load_json(CONFIG / "connectors" / connector / "fixtures/invariants.json")
    if fixture.get("schema_version") != 1:
        raise MonitorError("unsupported invariant backtest fixture")
    provider = PROVIDERS[connector](root)
    results = []
    for case in fixture["cases"]:
        artifact = "fixture:" + case["id"]
        text = normalize(case["text"])
        source = {
            "id": case.get("source", artifact),
            "url": case.get("url", artifact),
            "revision": digest(text),
            "text": text,
            "kind": "document",
        }
        previous = {**source, "text": normalize(case["before"])} if case.get("kind") == "document" else None
        if previous:
            previous["revision"] = digest(previous["text"])
            changes = candidates(source, previous)
        else:
            changes = [make_candidate(source, text.strip(), "release_note", version="2.1.300", line=1)]
        checks = [
            check for change in changes for check in provider.checks(change, source, previous, case.get("selected", []))
        ]
        rank = {"not_applicable": 0, "compatible": 1, "review_required": 2, "breaking_change": 3}
        actual = {}
        for check in checks:
            key = check["invariant_id"]
            if rank[check["verdict"]] > rank.get(actual.get(key), -1):
                actual[key] = check["verdict"]
        passed = all(actual.get(key) == value for key, value in case["expected"].items())
        # A guardrail case must not hide an unrelated false breaking verdict.
        passed = passed and all(
            value != "breaking_change" or case["expected"].get(key) == value for key, value in actual.items()
        )
        results.append(
            {"id": case["id"], "passed": passed, "expected": case["expected"], "actual": actual, "checks": checks}
        )
    return {
        "evaluation": fixture["evaluation"],
        "passed": sum(row["passed"] for row in results),
        "total": len(results),
        "cases": results,
    }


def markdown(report):
    lines = [
        f"# {report['connector']} upstream impact report",
        "",
        f"DefenseClaw: `{report['defenseclaw_revision']}`",
        f"Analysis: `{report['analysis_mode']}`; outcome: `{report['outcome']}`",
        "",
        report["coverage"],
        "",
        report["proof_scope"],
        "Keywords only select invariant checks. A breaking_change requires grounded local values "
        "and explicit upstream facts. "
        "Filtered means no manifest match, not proven compatibility.",
        "",
        f"Decisions: `{json.dumps(report['summary'], sort_keys=True)}`; AI calls: {report['ai_calls']}.",
        "",
    ]
    if "replay_scope" in report:
        lines.extend(["", "Replay scope: " + report["replay_scope"], ""])
    if "transitions" in report:
        lines.extend(
            [
                "",
                f"Historical parent-to-commit comparisons: {len(report['transitions'])}.",
                "",
                "| Commit | Change | Decisions | Gaps |",
                "| --- | --- | --- | --- |",
            ]
        )
        for transition in report["transitions"]:
            subject = str(transition.get("subject", ""))[:300]
            subject = (
                subject.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("@", "&#64;")
                .replace("|", "\\|")
                .replace("\n", " ")
            )
            lines.append(
                f"| `{transition['commit'][:12]}` | {subject} | "
                f"`{json.dumps(transition['summary'])}` | {transition['gaps']} |"
            )
    for source in report["sources"]:
        lines.append(f"- {source['id']}: {source['status']} ({source['revision']})")
    for gap in report["gaps"]:
        lines.extend(["", f"Collection gap: {gap['source']}: {gap['reason']}"])
    for row in report["findings"]:
        if row["decision"] == "filtered":
            continue
        candidate = row["candidate"]
        # Escape HTML/mentions; upstream Markdown is displayed as text, never executable workflow commands.
        text = candidate["text"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("@", "&#64;")
        lines.extend(
            [
                "",
                f"## {candidate.get('version', candidate['source'])}: {row['decision']}",
                "",
                f"Classes: {', '.join(row['artifact_classes'])}; analysis: {row['analysis_status']}.",
                "",
                *("> " + line for line in text.splitlines()),
                "",
                f"Source: {candidate['url']} (line {candidate.get('line', 'diff')})",
                "",
                "Local consumers: " + ", ".join(f"`{path}`" for path in row["local_artifacts"]),
            ]
        )
        if "analysis" in row:
            lines.extend(["", row["analysis"]["summary"]])
        for check in row["invariants"]:
            lines.extend(["", f"- `{check['invariant_id']}`: {check['verdict']} — {check['reason']}"])
            for claim in check["upstream_claims"]:
                ref = claim["evidence"][0]
                lines.append(
                    f"  - Upstream `{claim['kind']}` = `{json.dumps(claim['value'])}`: "
                    f"{ref['artifact']}:{ref['line']} ({ref['revision']})."
                )
            if check["verdict"] == "breaking_change":
                lines.append("  - Actual local binding: `" + json.dumps(check["local_values"], sort_keys=True) + "`.")
                lines.extend(
                    f"  - Local: `{ref['artifact']}:{ref['line']}` ({ref['revision']})."
                    for ref in check["local_evidence"][:3]
                )
    if "backtest" in report:
        lines.extend(
            [
                "",
                f"Backtest labels: {report['backtest']['passed']}/{report['backtest']['total']} passed.",
                report["backtest"]["evaluation"],
            ]
        )
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["collect", "collect-history", "analyze", "backtest", "backtest-invariants"])
    parser.add_argument("--connector", choices=sorted(PROVIDERS))
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--history", type=Path)
    parser.add_argument("--history-count", type=int, default=15)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--emit-prompts", type=Path)
    parser.add_argument(
        "--include-pr-inventory", action="store_true", help="collect bounded merged-PR file inventories"
    )
    parser.add_argument("--ai", choices=["off", "anthropic"], default="off")
    parser.add_argument("--model", default=os.environ.get("CONNECTOR_DELTA_MODEL", ""))
    parser.add_argument("--max-ai-calls", type=int, default=10)
    parser.add_argument(
        "--lookback", type=int, default=20, help="Initial release count; backtest always uses all releases in range"
    )
    parser.add_argument("--from-version")
    parser.add_argument("--to-version")
    parser.add_argument("--expectations", type=Path)
    parser.add_argument("--upstream-revision", help="collect only: pin the changelog to an exact upstream commit SHA")
    args = parser.parse_args(argv)
    try:
        paths = [
            path.resolve()
            for path in (args.output, args.snapshot, args.history, args.state, args.summary, args.expectations)
            if path
        ]
        if len(paths) != len(set(paths)):
            raise MonitorError("input, state and output paths must be distinct")
        if not 1 <= args.max_ai_calls <= 100 or not 1 <= args.lookback <= 1000:
            raise MonitorError("AI budget must be 1..100; initial lookback must be 1..1000")
        for version in (args.from_version, args.to_version):
            if version:
                version_tuple(version)
        if args.from_version and args.to_version and version_tuple(args.from_version) > version_tuple(args.to_version):
            raise MonitorError("from-version must not exceed to-version")
        manifest = load_manifest(
            args.manifest or CONFIG / "connectors" / (args.connector or "claudecode") / "manifest.json", args.repo
        )
        if args.connector and manifest["connector"] != args.connector:
            raise MonitorError("connector and manifest disagree")
        if args.command == "collect-history":
            from scripts.connector_delta.history import collect_history

            history = collect_history(manifest, request_text, collect, count=args.history_count)
            write_json(args.output, history)
            gaps = sum(len(snapshot["errors"]) for snapshot in history["snapshots"].values())
            print(
                json.dumps(
                    {
                        "transitions": len(history["cases"]),
                        "snapshots": len(history["snapshots"]),
                        "collection_gaps": gaps,
                    }
                )
            )
            return 2 if gaps else 0
        if args.command == "backtest-invariants":
            if args.state or args.snapshot or args.ai != "off":
                raise MonitorError("backtest-invariants is offline, stateless and deterministic")
            report = invariant_backtest(args.repo, connector=manifest["connector"])
            write_json(args.output, report)
            if args.summary:
                write_text(
                    args.summary,
                    "# Shared invariant mutation backtest\n\n"
                    + report["evaluation"]
                    + "\n\n"
                    + f"{report['passed']}/{report['total']} passed.\n\n"
                    + "\n".join(
                        f"- {case['id']}: {'PASS' if case['passed'] else 'FAIL'} — "
                        f"{json.dumps(case['actual'], sort_keys=True)}"
                        for case in report["cases"]
                    )
                    + "\n",
                )
            print(
                json.dumps({"passed": report["passed"], "total": report["total"], "evaluation": report["evaluation"]})
            )
            return 0 if report["passed"] == report["total"] else 2
        if args.upstream_revision and (
            args.command != "collect" or not re.fullmatch(r"[a-f0-9]{40}", args.upstream_revision)
        ):
            raise MonitorError("--upstream-revision is collect-only and must be an exact commit SHA")
        if args.command == "collect":
            inventory_state = load_json(args.state) if args.state and args.state.exists() else None
            snapshot = collect(
                manifest,
                revision_override=args.upstream_revision,
                include_inventory=args.include_pr_inventory,
                inventory_state=inventory_state,
            )
            write_json(args.output, snapshot)
            print(json.dumps({"collected": len(snapshot["sources"]), "gaps": snapshot["errors"]}))
            return 2 if snapshot["errors"] else 0
        if args.history:
            if (
                args.command != "backtest"
                or args.snapshot
                or args.state
                or args.ai != "off"
                or args.from_version
                or args.to_version
                or args.expectations
            ):
                raise MonitorError("--history requires an offline, stateless backtest without --snapshot")
            from scripts.connector_delta.history import replay_history

            report = replay_history(load_json(args.history), manifest, run_monitor, root=args.repo)
            write_json(args.output, report)
            if args.summary:
                write_text(args.summary, markdown(report))
            print(
                json.dumps(
                    {
                        "transitions": len(report["transitions"]),
                        "decisions": report["summary"],
                        "gaps": len(report["gaps"]),
                    }
                )
            )
            return 2 if report["gaps"] else 0
        if not args.snapshot:
            raise MonitorError(
                "analyze/backtest require an explicit --snapshot; replay never falls through to the network"
            )
        if args.command == "backtest" and args.state:
            raise MonitorError("backtest uses fresh state; --state is for analyze only")
        state = load_json(args.state) if args.state and args.state.exists() else None
        report, updated = run_monitor(
            load_json(args.snapshot),
            manifest,
            state,
            root=args.repo,
            ai=args.ai,
            model=args.model,
            max_ai=args.max_ai_calls,
            lookback=0 if args.command == "backtest" else args.lookback,
            lower=args.from_version,
            upper=args.to_version,
            prompts=args.emit_prompts,
        )
        if args.command == "backtest":
            report["replay_scope"] = "Historical upstream notes against current checkout; not an as-of-time experiment."
        if args.expectations:
            report["backtest"] = benchmark(report, load_json(args.expectations))
        write_json(args.output, report)
        if args.summary:
            write_text(args.summary, markdown(report))
        if args.state:
            write_json(args.state, updated)
        print(
            json.dumps(
                {
                    "outcome": report["outcome"],
                    "decisions": report["summary"],
                    "ai_calls": report["ai_calls"],
                    "backtest": {key: report["backtest"][key] for key in ("passed", "total")}
                    if "backtest" in report
                    else None,
                }
            )
        )
        return (
            2
            if report["gaps"] or ("backtest" in report and report["backtest"]["passed"] != report["backtest"]["total"])
            else 0
        )
    except (
        MonitorError,
        invariant_engine.InvariantError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        subprocess.CalledProcessError,
    ) as exc:
        print(f"connector delta monitor: {str(exc)[:240]}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
