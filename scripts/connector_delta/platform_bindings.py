# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Bounded readers for OS/deployment bindings in trusted checkout source only."""

import copy
import re

from .provider import _block, _mask_go


def function(provider, label, symbol, *required):
    """Unknown source shapes invalidate the binding instead of guessing values."""
    text = provider.sources[label][1]
    span = _block(text, symbol)
    body = _mask_go(text[slice(*span)], comments_only=True) if span else ""
    if not body or any(part not in body for part in required):
        return "", None
    return body, provider._ref(label, span)


def machine_paths(provider, symbol, windows_root):
    body, ref = function(provider, "machine_paths", symbol)
    # The entire return expression must be this recognized three-OS selector.
    match = re.fullmatch(
        r"func \w+\(opts Options\) \(string, error\)\s*\{\s*return machinePath\(opts,\s*"
        r'"([^"\n]+)",\s*"([^"\n]+)",\s*func\([^)]*\) string\s*\{\s*'
        r"return (programFiles|programData) \+ `([^`]+)`\s*\}\)\s*\}",
        body,
    )
    dispatch, dispatch_ref = function(
        provider,
        "machine_paths",
        "machinePath",
        'case "windows":',
        'case "darwin":',
        'case "linux":',
        "return windows(",
        "return rooted(opts, darwin)",
        "return rooted(opts, unix)",
    )
    if not match or not dispatch or match[3] != windows_root:
        return {}, []
    root = "%ProgramFiles%" if windows_root == "programFiles" else "%ProgramData%"
    return {"linux": match[1], "macos": match[2], "windows": root + match[4]}, [ref, dispatch_ref]


def binding(common, invariant, values, refs, verified=True, *, inherit=True):
    result = copy.deepcopy(common[invariant])
    result["values"] = {**result["values"], **values} if inherit else values
    result["evidence"] = (
        [*result["evidence"], *[ref for ref in refs if ref]] if inherit else [ref for ref in refs if ref]
    )
    result["verified"] = bool(verified and refs and all(refs) and (not inherit or result["verified"]))
    return result


def canonical_path(value, platform):
    # Symbolic roots only: never expand the monitoring runner's environment.
    value = value.replace("\\", "/").rstrip("/")
    if platform == "windows":
        value = re.sub(r"(?i)^(?:%USERPROFILE%|\$HOME)(?=/)", "~", value)
        value = value.casefold()
    return value
