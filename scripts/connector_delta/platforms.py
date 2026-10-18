# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Platform scope is a shared-invariant dimension, not OS certification."""

import copy
import re

from . import invariants
from .platform_bindings import canonical_path

PATTERNS = {
    "linux": r"\b(?:Linux|WSL[12]?)\b",
    "macos": r"\b(?:macOS|Darwin|Mac OS)\b",
    "windows": r"\bWindows\b|\bWin32\b|\bPowerShell\b",
}


def scope(text):
    return [name for name, pattern in PATTERNS.items() if re.search(pattern, text, re.IGNORECASE)]


def profiles(provider, bindings):
    cached = getattr(provider, "_platform_cache", None)
    if cached is None or cached[0] is not bindings:
        cached = (bindings, provider.platform_bindings(bindings))
        provider._platform_cache = cached
    return cached[1]


def coverage(provider):
    return {
        platform: {
            "status": "partial_static_coverage",
            "runtime_verified": False,
            "deployments": {
                deployment: {
                    invariant: {"verified": binding["verified"], "values": binding["values"]}
                    for invariant, binding in bindings.items()
                }
                for deployment, bindings in deployments.items()
            },
            "limitations": "Static file/launcher bindings only; higher-precedence MDM/registry/server policy "
            "and arbitrary quoting/control flow still require review. WSL uses Linux bindings.",
        }
        for platform, deployments in profiles(provider, provider.local()).items()
    }


def extract_scoped(provider, text, artifact, revision, *, base=0, full_text=None):
    """Only explicit, single-OS/single-deployment statements become scoped facts.

    Bare OS keywords, examples, fixes and conditional prose do not qualify.
    These deliberately narrow forms are also usable as mutation fixtures.
    """
    full_text = text if full_text is None else full_text
    result = []
    pattern = re.compile(
        r"^(?:- )?On (Windows|Linux|macOS|WSL2?), (user|managed|legacy managed) (?:command )?hooks "
        r"(are no longer read from `([^`\n]{1,500})`|no longer accept the `([A-Za-z_]{1,80})` registration key|"
        r"no longer accept `([A-Za-z.-]{1,80})` launchers)\.?$",
        re.MULTILINE,
    )
    for match in pattern.finditer(text):
        if text[: match.start()].count("```") % 2:
            continue
        invariant, kind, value = (
            ("hook.discovery", "retired_path", match[4])
            if match[4]
            else ("hook.registration", "retired_registration_key", match[5])
            if match[5]
            else ("hook.execution", "launcher_rejected", match[6])
        )
        ref = invariants.evidence(
            full_text,
            base + match.start(),
            base + match.end(),
            artifact=artifact,
            revision=revision,
            role="upstream",
            authority="explicit_statement",
        )
        result.append(
            {
                "invariant_id": invariant,
                "kind": kind,
                "value": value,
                "authority": "explicit_statement",
                "evidence": [ref],
                "platforms": scope(match[1]),
                "deployment_scope": "managed-legacy" if match[2] == "legacy managed" else match[2],
            }
        )
    return result


def evaluate(provider, bindings, claims, selected, text):
    platforms = scope(text)
    local = copy.deepcopy(bindings)
    scoped = [claim for claim in claims if "deployment_scope" in claim or "platforms" in claim]
    if scoped:
        checks = []
        matrix = profiles(provider, bindings)
        for invariant in dict.fromkeys(selected):
            targeted = [claim for claim in scoped if claim["invariant_id"] == invariant]
            if not targeted:
                # Other selected requirements remain unresolved, not borrowed
                # from a different platform or from adjacent prose.
                unresolved = evaluate(
                    provider, bindings, [claim for claim in claims if claim not in scoped], [invariant], text
                )
                checks.extend(unresolved)
                continue
            dimensions = {(tuple(claim.get("platforms", [])), claim.get("deployment_scope")) for claim in targeted}
            for target_platforms, deployment in sorted(dimensions, key=str):
                for platform in target_platforms or ("unspecified",):
                    bound = copy.deepcopy(bindings)
                    profile = matrix.get(platform, {}).get(deployment, {})
                    for key in ("hook.discovery", "hook.registration", "hook.execution"):
                        bound[key] = copy.deepcopy(profile.get(key, {**bound[key], "verified": False}))
                        bound[key]["scope"] = f"{platform}/{deployment}"
                    facts = copy.deepcopy(
                        [
                            claim
                            for claim in targeted
                            if tuple(claim.get("platforms", [])) == target_platforms
                            and claim.get("deployment_scope") == deployment
                        ]
                    )
                    if invariant == "hook.discovery":
                        bound[invariant]["values"]["paths"] = [
                            canonical_path(path, platform) for path in bound[invariant]["values"].get("paths", [])
                        ]
                        for fact in facts:
                            if isinstance(fact.get("value"), str):
                                fact["value"] = canonical_path(fact["value"], platform)
                                if (
                                    platform == "windows"
                                    and re.match(r"^[a-z]:/", fact["value"])
                                    and any(
                                        path.startswith("%") for path in bound[invariant]["values"].get("paths", [])
                                    )
                                ):
                                    # API-resolved installation roots are symbolic. A literal
                                    # C: path cannot prove either equality or non-impact.
                                    bound[invariant]["verified"] = False
                    rows = invariants.evaluate(
                        provider.catalog,
                        bound,
                        facts,
                        selected=[invariant],
                        transport=provider.transport,
                        texts=provider.texts,
                    )
                    for row in rows:
                        row.update(platforms=[platform], deployment_scope=deployment)
                    checks.extend(rows)
        return checks
    if platforms:
        # Common user bindings do not verify managed loaders or native shell /
        # argv contracts. An OS-scoped path or launch claim must remain review.
        for key in ("hook.discovery", "hook.registration", "hook.execution"):
            local[key]["verified"] = False
    checks = invariants.evaluate(
        provider.catalog, local, claims, selected=selected, transport=provider.transport, texts=provider.texts
    )
    for check in checks:
        check["platforms"] = platforms or ["unspecified"]
        if platforms and check["invariant_id"] in {"hook.discovery", "hook.registration", "hook.execution"}:
            check["reason"] = (
                "OS-specific discovery/registration/execution needs explicit OS and deployment scope; "
                "nearby keywords do not select a verified binding."
            )
    return checks
