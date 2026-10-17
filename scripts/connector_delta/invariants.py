#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Vendor-neutral, evidence-gated comparisons of connector behavior contracts.

Providers extract local bindings and upstream claims. This engine does not know
Claude event names, configuration paths or JSON response keys, and never calls
an LLM. 'breaking_change' means a documented contract conflict, not a verified
live-client regression. Partial inventories and examples cannot prove removal.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

CATALOG = Path(__file__).resolve().parent / "shared/invariants.json"
PROVEN = {"explicit_statement", "declared_schema", "contract_table"}
KINDS = {
    "hook.discovery": {"accepted_paths", "retired_path", "exclusive_paths", "default_directory"},
    "hook.registration": {"retired_registration_key", "accepted_registration_key"},
    "hook.event_delivery": {"event_removed", "event_added", "event_inventory"},
    "hook.payload": {"field_type", "field_removed"},
    "hook.decision": {"decision_rejected", "decision_accepted", "response_field_validated"},
    "hook.execution": {"event_phase", "synchronous", "hard_timeout_seconds", "default_timeout_seconds"},
    "hook.failure": {"exit_code_blocks"},
    "hook.correlation": {"field_type", "field_removed"},
}


class InvariantError(ValueError):
    """A malformed binding or ungrounded claim is never a compatible result."""


def load_catalog(path=CATALOG):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise InvariantError("unsupported invariant catalog")
    rows = data.get("invariants", [])
    result = {row["id"]: row for row in rows}
    if len(result) != len(rows) or not rows:
        raise InvariantError("invariant IDs must be unique and nonempty")
    return result


def evidence(text, start, end, *, artifact, revision, role, authority):
    """Pin exact character offsets plus line numbers; never just a loose quote."""
    quote = text[start:end]
    if not quote or not 0 <= start < end <= len(text):
        raise InvariantError("invalid evidence span")
    return {
        "artifact": artifact,
        "revision": revision,
        "role": role,
        "authority": authority,
        "line": text[:start].count("\n") + 1,
        "quote": quote,
        "start": start,
        "end": end,
    }


def checked_claim(claim, texts):
    """Reject claims whose source span, revision, line or quote was invented."""
    refs = claim.get("evidence", []) if isinstance(claim, dict) else None
    if not isinstance(refs, list) or not refs:
        return False
    for ref in refs:
        if not isinstance(ref, dict) or any(not isinstance(ref.get(key), str) for key in ("artifact", "revision")):
            return False
        text = texts.get((ref.get("artifact"), ref.get("revision")))
        start, end = ref.get("start"), ref.get("end")
        if (
            text is None
            or type(start) is not int
            or type(end) is not int
            or type(ref.get("line")) is not int
            or not 0 <= start < end <= len(text)
            or text[start:end] != ref.get("quote")
            or text[:start].count("\n") + 1 != ref.get("line")
        ):
            return False
    return True


def valid_fact(claim, invariant_id):
    kind, value = claim.get("kind"), claim.get("value")
    if not isinstance(claim.get("authority"), str) or claim["authority"] not in PROVEN | {"example"}:
        return False
    if (
        claim.get("invariant_id") != invariant_id
        or not isinstance(kind, str)
        or kind not in KINDS.get(invariant_id, set())
    ):
        return False
    if any(
        ref.get("role") != "upstream" or ref.get("authority") != claim.get("authority") for ref in claim["evidence"]
    ):
        return False
    if kind in {"accepted_paths", "exclusive_paths", "event_inventory"}:
        return isinstance(value, list) and bool(value) and all(isinstance(item, str) and item for item in value)
    if kind in {"event_removed", "event_added", "field_removed", "response_field_validated"}:
        valid = value is None
    elif kind in {"synchronous", "exit_code_blocks"}:
        valid = type(value) is bool
    elif kind in {"hard_timeout_seconds", "default_timeout_seconds"}:
        valid = type(value) is int and value > 0
    elif kind in {"decision_rejected", "decision_accepted"}:
        valid = isinstance(value, str) and bool(value) or type(value) is bool
    else:
        valid = isinstance(value, str) and bool(value)
    if kind == "field_type":
        valid = valid and value in {"string", "object", "array", "number", "boolean", "null"}
    if kind == "event_phase":
        valid = valid and value in {"before", "after"}
    if kind not in {"retired_path", "retired_registration_key", "accepted_registration_key", "default_directory"}:
        valid = valid and isinstance(claim.get("event"), str) and bool(claim["event"])
    if kind in {"field_type", "field_removed", "decision_rejected", "decision_accepted", "response_field_validated"}:
        valid = valid and isinstance(claim.get("field"), str) and bool(claim["field"])
    if kind == "exit_code_blocks":
        valid = valid and type(claim.get("exit_code")) is int
    return bool(valid)


def _result(definition, binding, claims, verdict, reason, **extra):
    return {
        "invariant_id": definition["id"],
        "name": definition["name"],
        "scope": binding.get("scope", "unknown"),
        "verdict": verdict,
        "impact": definition["severity"]
        if verdict == "breaking_change"
        else "unknown"
        if verdict == "review_required"
        else "none",
        "proof_scope": "static_contract_comparison",
        "runtime_verified": False,
        "reason": reason,
        "local_values": binding.get("values", {}),
        "local_binding_verified": bool(binding.get("verified")),
        "local_evidence": binding.get("evidence", []),
        "upstream_claims": claims,
        **extra,
    }


def compare(definition, binding, claims, *, transport, texts):
    """Compare one shared invariant with a provider's evidence-backed facts.

    Local providers must report unverified extraction explicitly. A provider may
    assert positive facts from tables, but absence from a table or JSON example
    is insufficient to assert removal. Events/fields not consumed locally are
    outside the affected binding, not regressions merely because they changed.
    """
    if transport not in definition["applies_to"] or binding.get("applicable") is False:
        return _result(definition, binding, [], "not_applicable", "Invariant does not apply to this transport/binding.")
    if (
        not binding.get("verified")
        or not checked_claim(binding, texts)
        or any(ref.get("role") != "local" or ref.get("authority") != "local_code" for ref in binding["evidence"])
    ):
        return _result(
            definition,
            {**binding, "verified": False},
            [],
            "review_required",
            "Local implementation binding could not be verified.",
        )
    if any(not checked_claim(claim, texts) for claim in claims):
        return _result(
            definition,
            binding,
            [],
            "review_required",
            "Upstream evidence is missing or does not match its source span.",
        )
    if not claims:
        return _result(
            definition,
            binding,
            [],
            "review_required",
            "No explicit contract fact was extracted for this changed artifact.",
        )
    if any(not valid_fact(claim, definition["id"]) for claim in claims):
        return _result(
            definition, binding, [], "review_required", "A claim has an unsupported shape, scope or evidence authority."
        )
    values = binding["values"]
    judgments = []
    for claim in claims:
        authority = claim.get("authority")
        if authority not in PROVEN:
            judgments.append(
                ("review_required", "Example, omission or ambiguous prose is not an authoritative contract change.")
            )
            continue
        kind, value = claim.get("kind"), claim.get("value")
        event = claim.get("event")
        relevant = event is None or event in values.get("events", [event])
        if not relevant:
            judgments.append(("compatible", "The changed event is outside this connector's declared binding."))
            continue
        if kind == "default_directory":
            directories = {path.rsplit("/", 1)[0] for path in values.get("paths", []) if "/" in path}
            judgments.append(
                (
                    "compatible" if value in directories else "review_required",
                    "The default directory still matches the registration root."
                    if value in directories
                    else "The host default directory differs from the writer; legacy-path or migration support "
                    "must be established before claiming retirement.",
                )
            )
        elif kind == "accepted_paths":
            if set(value) & set(values.get("paths", [])):
                judgments.append(("compatible", "The host still accepts the actual registration location."))
            else:
                judgments.append(
                    (
                        "review_required",
                        "The local path is absent from this inventory; legacy-path support is not disproven.",
                    )
                )
        elif kind == "retired_path":
            broken = value in values.get("paths", [])
            judgments.append(
                (
                    "breaking_change" if broken else "compatible",
                    "The host explicitly stops reading the path written by this connector."
                    if broken
                    else "The retired path is not the path this binding writes.",
                )
            )
        elif kind == "exclusive_paths":
            broken = not set(value) & set(values.get("paths", []))
            judgments.append(
                (
                    "breaking_change" if broken else "compatible",
                    "The host's explicit accepted-path set excludes this registration."
                    if broken
                    else "At least one actual registration location is explicitly accepted.",
                )
            )
        elif kind == "retired_registration_key":
            broken = value in values.get("keys", [])
            judgments.append(
                (
                    "breaking_change" if broken else "compatible",
                    "The host explicitly rejects a key the connector emits."
                    if broken
                    else "The retired key is not emitted.",
                )
            )
        elif kind == "accepted_registration_key":
            judgments.append(
                (
                    "compatible" if value in values.get("keys", []) else "review_required",
                    "Compare the host's accepted registration key with the local writer.",
                )
            )
        elif kind in {"event_removed", "event_added"}:
            owned = event in values.get("events", [])
            judgments.append(
                (
                    "breaking_change" if kind == "event_removed" and owned else "compatible",
                    "A required registered event is explicitly removed."
                    if kind == "event_removed" and owned
                    else "The added event is already registered."
                    if owned
                    else "An additive event is not removal of existing coverage.",
                )
            )
        elif kind == "event_inventory":
            missing = set(values.get("events", [])) - set(value)
            judgments.append(
                (
                    "review_required" if missing else "compatible",
                    "Inventory omission cannot establish event removal."
                    if missing
                    else "All bound events remain listed.",
                )
            )
        elif kind in {"field_type", "field_removed"}:
            field = claim.get("field")
            accepted = values.get("fields", {}).get(field)
            if accepted is None:
                judgments.append(("compatible", "The changed field is not part of the consumed binding."))
            else:
                if kind == "field_removed" and field not in values.get("required_fields", []):
                    judgments.append(
                        (
                            "review_required",
                            "Removal of a consumed optional field needs behavioral review; "
                            "omission does not itself fail decoding.",
                        )
                    )
                    continue
                broken = kind == "field_removed" or value not in accepted
                judgments.append(
                    (
                        "breaking_change" if broken else "compatible",
                        "A consumed field is removed or has a type the local decoder cannot accept."
                        if broken
                        else "The supplied field type is accepted by the current decoder.",
                    )
                )
        elif kind in {"decision_rejected", "decision_accepted", "response_field_validated"}:
            field = claim.get("field")
            emitted = values.get("responses", {}).get(event, {})
            affected = field in emitted and (kind == "response_field_validated" or emitted[field] == value)
            if kind == "response_field_validated" and affected:
                judgments.append(
                    (
                        "review_required",
                        "The connector emits the newly validated field; its value constraints need review.",
                    )
                )
            else:
                broken = kind == "decision_rejected" and affected
                judgments.append(
                    (
                        "breaking_change" if broken else "compatible",
                        "The host explicitly ignores the exact blocking response this connector emits."
                        if broken
                        else "The accepted decision matches, or the changed encoding is not emitted by this binding.",
                    )
                )
        elif kind in {"event_phase", "synchronous", "hard_timeout_seconds", "default_timeout_seconds"}:
            if kind == "default_timeout_seconds":
                explicit = event in values.get("timeouts", {})
                judgments.append(
                    (
                        "compatible" if explicit else "review_required",
                        "An explicit per-event timeout is used; changing only the default does not shorten it."
                        if explicit
                        else "No explicit local timeout was verified for this event.",
                    )
                )
            else:
                if kind == "event_phase" and event not in values.get("expected_phases", {}):
                    judgments.append(
                        ("review_required", "This event's expected execution phase has not been bound locally.")
                    )
                    continue
                broken = (
                    (kind == "event_phase" and value != values["expected_phases"][event])
                    or (kind == "synchronous" and value is False and event in values.get("barrier_events", []))
                    or (
                        kind == "hard_timeout_seconds"
                        and event in values.get("timeouts", {})
                        and value < values["timeouts"][event]
                    )
                )
                judgments.append(
                    (
                        "breaking_change" if broken else "compatible",
                        "The host no longer preserves the connector's pre-action wait or explicit budget."
                        if broken
                        else "This bound execution requirement remains satisfied.",
                    )
                )
        elif kind == "exit_code_blocks":
            broken = value is False and claim.get("exit_code") in values.get("blocking_exit_codes", [])
            judgments.append(
                (
                    "breaking_change" if broken else "compatible",
                    "The host explicitly stops honoring the connector's blocking exit code."
                    if broken
                    else "The changed exit status does not invalidate the declared blocking failure behavior.",
                )
            )
        else:
            judgments.append(("review_required", "The extracted claim has no implemented deterministic comparator."))
    verdict = (
        "breaking_change"
        if any(v == "breaking_change" for v, _ in judgments)
        else ("review_required" if any(v == "review_required" for v, _ in judgments) else "compatible")
    )
    reason = next(reason for value, reason in judgments if value == verdict)
    return _result(
        definition,
        binding,
        claims,
        verdict,
        reason,
        comparisons=[{"verdict": verdict, "reason": reason} for verdict, reason in judgments],
    )


def evaluate(catalog, local, claims, *, selected, transport, texts):
    results = []
    for invariant_id in dict.fromkeys(selected):
        if invariant_id not in catalog:
            raise InvariantError("unknown shared invariant ID")
        binding = copy.deepcopy(local.get(invariant_id, {"verified": False}))
        related = [claim for claim in claims if claim.get("invariant_id") == invariant_id]
        results.append(compare(catalog[invariant_id], binding, related, transport=transport, texts=texts))
    return results
