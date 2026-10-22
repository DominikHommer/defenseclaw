# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""until 1.1: what the removed OpenHands and OmniGent connectors leave on a host.

DefenseClaw 1.0.4 removed both connectors (#1182). Their teardown
(``internal/gateway/connector/removed.go``) does two things only: it replaces
the hook script an older DefenseClaw wrote (OpenHands' ``openhands-hook.sh``,
OmniGent's policy module), proven by its DefenseClaw marker, with a stub that
blocks every call, and it revokes the connector's tokens. Everything else
stays. :func:`leftovers` lists it, with the step to remove each item by hand,
for ``defenseclaw status``, ``defenseclaw doctor`` and ``defenseclaw
uninstall``. It only reads. The Go side lists the same for ``connector
teardown`` and Windows Setup (``RemovedConnectorLeftovers``). Delete this
module in 1.1.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

_READ_LIMIT = 16 << 20
_SCRIPT_LIMIT = 1 << 20
_MARKER_LINES = 3
# Every stub the 1.0.4 teardown writes says this; the stubs an older teardown
# left (they allowed every call) do not.
STUB_PHRASE = "support was removed in DefenseClaw 1.0.4"
_MODULE = "defenseclaw_omnigent_policy"
_POLICY_KEY = "defenseclaw_guardrail"


@dataclass(frozen=True)
class _Removed:
    name: str
    label: str
    script: str
    marker: str
    config_file: str
    default_dir: str
    needles: tuple[str, ...]
    config_what: str
    config_step: str


_CONNECTORS: tuple[_Removed, ...] = (
    _Removed(
        name="openhands",
        label="OpenHands",
        script="openhands-hook.sh",
        marker="# defenseclaw-managed-hook v",
        config_file="hooks.json",
        default_dir=".openhands",
        # Windows registered the native launcher, not the script.
        needles=("openhands-hook.sh", "--connector openhands"),
        config_what="OpenHands still runs DefenseClaw's hook from here; it blocks every call",
        config_step=(
            "remove every hook whose command runs openhands-hook.sh (or defenseclaw-hook --connector openhands) "
            "from this file, then restart OpenHands"
        ),
    ),
    _Removed(
        name="omnigent",
        label="OmniGent",
        script=_MODULE + ".py",
        marker="# defenseclaw-managed-policy v",
        config_file="config.yaml",
        default_dir=".omnigent",
        needles=(_MODULE,),
        config_what="OmniGent still imports DefenseClaw's policy module from here; it denies every request",
        config_step=(
            f"remove {_MODULE} from policy_modules and the {_POLICY_KEY} policy (handler "
            f"{_MODULE}.defenseclaw_policy) from this file, then restart OmniGent"
        ),
    ),
)

NAMES: tuple[str, ...] = tuple(c.name for c in _CONNECTORS)


@dataclass(frozen=True)
class Leftover:
    path: str
    what: str
    step: str


@dataclass(frozen=True)
class RemovedConnectorLeftovers:
    """What one removed connector left on this host."""

    connector: str
    label: str
    items: tuple[Leftover, ...]

    def as_json(self) -> dict:
        return {
            "connector": self.connector,
            "label": self.label,
            "items": [{"path": i.path, "what": i.what, "step": i.step} for i in self.items],
        }

    def lines(self, *, without_under: str = "") -> list[str]:
        """Text lines for a person; items under *without_under* are left out."""
        items = [i for i in self.items if not (without_under and _is_under(i.path, without_under))]
        if not items:
            return []
        return [f"{self.label} support was removed in DefenseClaw 1.0.4. Left for you to remove by hand:"] + [
            f"  - {i.path}: {i.what}. To remove: {i.step}." for i in items
        ]


def _is_under(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([os.path.abspath(path), os.path.abspath(root)]) == os.path.abspath(root)
    except ValueError:
        return False


def _key(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _absolute(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    return os.path.abspath(os.path.expanduser(value))


def _json_file(path: str) -> dict:
    try:
        if os.path.getsize(path) > _READ_LIMIT:
            return {}
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _backup_target(data_dir: str, name: str, logical: str) -> str:
    record = _json_file(os.path.join(data_dir, "connector_backups", name, logical + ".json"))
    if record.get("connector") != name or record.get("logical_name") != logical:
        return ""
    path = record.get("path")
    return path.strip() if isinstance(path, str) else ""


def _lock_config_paths(data_dir: str, c: _Removed) -> list[str]:
    lock = _json_file(os.path.join(data_dir, "hook_contract_lock.json"))
    connectors = lock.get("connectors")
    entry = connectors.get(c.name) if isinstance(connectors, dict) else None
    locations = entry.get("locations") if isinstance(entry, dict) else None
    paths = locations.get("hook_config_paths") if isinstance(locations, dict) else None
    if not isinstance(paths, list):
        return []
    return [_absolute(p) for p in paths if isinstance(p, str) and os.path.basename(p).lower() == c.config_file]


def _config_paths(data_dir: str, c: _Removed, home: str) -> list[str]:
    paths: list[str] = []
    if data_dir:
        paths.append(_backup_target(data_dir, c.name, "config"))
        paths.extend(_lock_config_paths(data_dir, c))
    paths.append(os.path.join(home, c.default_dir, c.config_file))
    if c.name == "omnigent":
        paths.append(_absolute(os.environ.get("OMNIGENT_CONFIG", "")))
        env_home = _absolute(os.environ.get("OMNIGENT_CONFIG_HOME", ""))
        if env_home:
            paths.append(os.path.join(env_home, c.config_file))
    out: list[str] = []
    seen: set[str] = set()
    for path in paths:
        if path and _key(path) not in seen:
            seen.add(_key(path))
            out.append(path)
    return out


def _script_state(path: str, c: _Removed) -> str:
    """absent, stub, owned (an older release wrote it), foreign, or an error text."""
    if not os.path.lexists(path):
        return "absent"
    if os.path.islink(path) or not os.path.isfile(path):
        return "foreign"
    try:
        if os.path.getsize(path) > _SCRIPT_LIMIT:
            return "foreign"
        with open(path, "rb") as fh:
            data = fh.read(_SCRIPT_LIMIT + 1)
    except OSError as exc:
        return f"could not be read ({exc})"
    head = data.split(b"\n", _MARKER_LINES)[:_MARKER_LINES]
    if not any(line.strip().startswith(c.marker.encode()) for line in head):
        return "foreign"
    return "stub" if STUB_PHRASE.encode() in data else "owned"


def _leftovers_of(data_dir: str, c: _Removed, home: str) -> list[Leftover]:
    items: list[Leftover] = []
    teardown = f"run defenseclaw-gateway connector teardown --connector {c.name}"
    for path in _config_paths(data_dir, c, home):
        try:
            if not os.path.exists(path):
                continue
            with open(path, "rb") as fh:
                data = fh.read(_READ_LIMIT)
        except OSError as exc:
            items.append(Leftover(path, f"could not be read ({exc})", "check it by hand: " + c.config_step))
            continue
        if any(needle.encode() in data for needle in c.needles):
            items.append(Leftover(path, c.config_what, c.config_step))
    if c.name == "omnigent" and data_dir:
        pth = _backup_target(data_dir, c.name, "pth")
        if pth and os.path.lexists(pth):
            items.append(
                Leftover(
                    pth,
                    "adds DefenseClaw's hook folder to OmniGent's Python import path",
                    f"delete this file once no OmniGent config.yaml names {_MODULE}",
                )
            )
    if not data_dir:
        return items
    hooks = os.path.join(data_dir, "hooks")
    script = os.path.join(hooks, c.script)
    state = _script_state(script, c)
    if state == "stub":
        items.append(Leftover(script, f"the stub that blocks every {c.label} call", "delete it once nothing above runs it"))
    elif state == "owned":
        items.append(Leftover(script, "still the hook script an older DefenseClaw wrote", teardown))
    elif state == "foreign":
        items.append(
            Leftover(
                script,
                "not changed: it is not a file DefenseClaw wrote (no DefenseClaw marker, or a link)",
                "remove what runs it, then delete it if it is not yours",
            )
        )
    elif state != "absent":
        items.append(Leftover(script, state, "delete it once nothing above runs it"))
    if c.name == "openhands":
        record = os.path.join(hooks, ".hookcfg.openhands")
        if os.path.lexists(record):
            items.append(Leftover(record, "the runtime settings of the removed hook; DefenseClaw no longer reads it", "delete it"))
    backups = os.path.join(data_dir, "connector_backups", c.name)
    if os.path.lexists(backups):
        items.append(
            Leftover(
                backups,
                "the copies of your files DefenseClaw saved before its setup changed them (pristine_bytes, base64)",
                "copy back what you need, then delete this folder",
            )
        )
    for token in (os.path.join(hooks, f".hook-{c.name}.token"), os.path.join(hooks, f".otlp-{c.name}.token")):
        if os.path.lexists(token):
            items.append(Leftover(token, "a DefenseClaw token for the removed connector", teardown))
    return items


def leftovers(data_dir: str, *, home: str | None = None) -> list[RemovedConnectorLeftovers]:
    """Return what each removed connector left on this host (none when nothing is left)."""
    home = home or os.path.expanduser("~")
    out: list[RemovedConnectorLeftovers] = []
    for c in _CONNECTORS:
        items = _leftovers_of(data_dir or "", c, home)
        if items:
            out.append(RemovedConnectorLeftovers(c.name, c.label, tuple(items)))
    return out
