# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Platform scope is a shared-invariant dimension, not OS certification."""

import copy
import re

from . import invariants

PATTERNS = {
    "linux": r"\b(?:Linux|WSL[12]?)\b",
    "macos": r"\b(?:macOS|Darwin|Mac OS)\b",
    "windows": r"\bWindows\b|\bWin32\b|\bPowerShell\b",
}


def scope(text):
    return [name for name, pattern in PATTERNS.items() if re.search(pattern, text, re.IGNORECASE)]


def evaluate(provider, bindings, claims, selected, text):
    platforms = scope(text)
    local = copy.deepcopy(bindings)
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
                "OS-specific discovery/registration/execution needs a platform-specific binding; "
                "common values do not certify it."
            )
    return checks
