# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""until 1.1: manual cleanup left by the removed OpenHands and OmniGent connectors.

DefenseClaw 1.0.4 removed both connectors (#1182). The gateway's teardown
(``internal/gateway/connector/removed.go``) changes an agent file only when its
bytes are exactly what an older DefenseClaw setup wrote. Otherwise it changes
nothing and records the steps to finish by hand in
``<data_dir>/removed_connector_cleanup/<connector>.json``. ``defenseclaw status``
and ``defenseclaw doctor`` show that record. Delete this module in 1.1.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

CLEANUP_DIR = "removed_connector_cleanup"
_CONNECTORS: tuple[tuple[str, str], ...] = (("omnigent", "OmniGent"), ("openhands", "OpenHands"))
_MAX_BYTES = 1 << 20


@dataclass(frozen=True)
class CleanupItem:
    path: str
    reason: str
    step: str


@dataclass(frozen=True)
class PendingCleanup:
    """One removed connector whose files the user must finish cleaning up."""

    connector: str
    label: str
    record: str
    finish: str
    items: tuple[CleanupItem, ...] = ()
    error: str = ""

    def as_json(self) -> dict:
        return {
            "connector": self.connector,
            "label": self.label,
            "record": self.record,
            "finish": self.finish,
            "items": [{"path": i.path, "reason": i.reason, "step": i.step} for i in self.items],
            **({"error": self.error} if self.error else {}),
        }


def pending_cleanup(data_dir: str) -> list[PendingCleanup]:
    """Return the manual cleanup each removed connector's teardown recorded."""
    if not data_dir:
        return []
    out: list[PendingCleanup] = []
    for name, label in _CONNECTORS:
        path = os.path.join(data_dir, CLEANUP_DIR, name + ".json")
        finish = f"defenseclaw-gateway connector teardown --connector {name}"
        try:
            if os.path.getsize(path) > _MAX_BYTES:
                raise ValueError("record is too large")
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
            if not isinstance(doc, dict):
                raise ValueError("record is not a JSON object")
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            out.append(PendingCleanup(name, label, path, finish, error=f"could not read {path}: {exc}"))
            continue
        items = tuple(
            CleanupItem(str(raw.get("path") or ""), str(raw.get("reason") or ""), str(raw.get("step") or ""))
            for raw in (doc.get("items") or [])
            if isinstance(raw, dict) and raw.get("path")
        )
        out.append(
            PendingCleanup(
                connector=name,
                label=str(doc.get("label") or label),
                record=path,
                finish=str(doc.get("finish") or finish),
                items=items,
            )
        )
    return out
