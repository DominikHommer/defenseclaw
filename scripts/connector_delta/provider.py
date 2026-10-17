# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Trusted provider utilities. Downloaded source is data, never imported."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from scripts.connector_delta import invariants as engine

CONFIG = Path(__file__).resolve().parent


def _sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _mask_go(text):
    token = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
    return token.sub(lambda match: "".join("\n" if char == "\n" else " " for char in match[0]), text)


def _block(text, symbol, *, struct=False):
    masked = _mask_go(text)
    prefix = rf"\btype\s+{re.escape(symbol)}\s+struct\s*\{{" if struct else rf"\bfunc\s+{re.escape(symbol)}\s*\("
    match = re.search(prefix, masked)
    if not match:
        return None
    if struct:
        opening = match.end() - 1
    else:
        body = re.search(r"\{\s*\n", masked[match.end() :])
        if not body:
            return None
        opening = match.end() + body.start()
    depth = 0
    for index in range(opening, len(masked)):
        depth += (masked[index] == "{") - (masked[index] == "}")
        if depth == 0:
            return match.start(), index + 1
    return None


class CommandHookProvider:
    def __init__(self, root, binding_path, connector):
        self.root = Path(root).resolve()
        self.spec = json.loads(Path(binding_path).read_text(encoding="utf-8"))
        if self.spec.get("schema_version") != 1 or self.spec.get("connector") != connector:
            raise engine.InvariantError("unsupported provider invariant binding")
        self.transport = self.spec["transport"]
        self.texts, self.sources, self.local_cache = {}, {}, {}
        for label, relative in self.spec["local_sources"].items():
            path = (self.root / relative).resolve()
            if not path.is_relative_to(self.root) or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
                raise engine.InvariantError("local invariant source is missing, oversized or outside the checkout")
            text = path.read_text(encoding="utf-8")
            self.sources[label] = (relative, text, _sha(text))
            self.texts[(relative, _sha(text))] = text
        self.registry = json.loads(self.sources["registry"][1])["connectors"][connector]
        self.catalog = engine.load_catalog()
        self.platform_coverage = {
            name: {
                "status": "partial_static_coverage",
                "runtime_verified": False,
                "scope": "Common command-hook wire contract; user registration only",
                "limitations": (
                    "Managed discovery and OS-native launching/quoting are not fully modeled. "
                    "WSL is Linux, not native Windows."
                ),
            }
            for name in ("linux", "macos", "windows")
        }

    def _ref(self, label, span=None):
        path, text, revision = self.sources[label]
        start, end = span or (0, len(text))
        return engine.evidence(text, start, end, artifact=path, revision=revision, role="local", authority="local_code")

    def _function(self, label, selector):
        _, text, _ = self.sources[label]
        span = _block(text, self.spec["selectors"][selector])
        return (text[slice(*span)], self._ref(label, span)) if span else ("", None)

    def _binding(self, invariant_id, values, refs, verified=True):
        spec = next(row for row in self.spec["bindings"] if row["id"] == invariant_id)
        return {
            "scope": spec["scope"],
            "values": values,
            "evidence": [ref for ref in refs if ref],
            "verified": bool(verified and refs and all(refs)),
            "applicable": True,
        }

    def _contract(self, version=None):
        contracts = self.registry["contracts"]
        if version and re.fullmatch(r"\d+\.\d+\.\d+", version):
            current = tuple(map(int, version.split(".")))
            for contract in contracts:
                lower = tuple(map(int, contract["agent_version"]["min_inclusive"].split(".")))
                ceiling = contract["agent_version"].get("max_exclusive")
                if current >= lower and (not ceiling or current < tuple(map(int, ceiling.split(".")))):
                    return contract
            return None
        return max(contracts, key=lambda row: tuple(map(int, row["agent_version"]["min_inclusive"].split("."))))

    def selected(self, artifact_classes):
        return [row["id"] for row in self.spec["bindings"] if set(row["artifact_classes"]) & set(artifact_classes)]

    def registry_ref(self, contract):
        text = self.sources["registry"][1]
        start = text.index('"contract_id": "' + contract["contract_id"] + '"')
        start = text.rfind("{", 0, start)
        _, consumed = json.JSONDecoder().raw_decode(text[start:])
        return self._ref("registry", (start, start + consumed))
