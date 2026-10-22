# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Trusted packaged ACP inventory shared by CLI and TUI presentation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files
from typing import Any


@dataclass(frozen=True)
class ACPEntryCapabilities:
    entries_key: str
    managed_type: str
    launch_keys: frozenset[str]
    preference_keys: frozenset[str]


def _load_catalog() -> tuple[
    dict[str, Any], tuple[str, ...], dict[str, tuple[str, tuple[str, ...]]], dict[str, ACPEntryCapabilities]
]:
    """Load the packaged ACP inventory once and fail closed on shape drift."""
    try:
        registry = json.loads(
            files("defenseclaw.inventory").joinpath("acp_registry.json").read_text(encoding="utf-8")
        )
        for item in registry["clients"]:
            capability = item["entry_capabilities"]
            if (
                not isinstance(capability, dict)
                or set(capability) != {"entries_key", "managed_type", "launch_keys", "preference_keys"}
                or not isinstance(capability["entries_key"], str)
                or not isinstance(capability["managed_type"], str)
                or any(
                    not isinstance(capability[key], list)
                    or not all(isinstance(value, str) and value for value in capability[key])
                    or len(capability[key]) != len(set(capability[key]))
                    for key in ("launch_keys", "preference_keys")
                )
            ):
                raise ValueError("invalid editor entry capabilities")
        clients = tuple(sorted(item["id"] for item in registry["clients"]))
        agents = {
            item["id"]: (item["command"], tuple(item["args"]))
            for item in registry["agents"]
        }
        capabilities = {
            item["id"]: ACPEntryCapabilities(
                entries_key=item["entry_capabilities"]["entries_key"],
                managed_type=item["entry_capabilities"]["managed_type"],
                launch_keys=frozenset(item["entry_capabilities"]["launch_keys"]),
                preference_keys=frozenset(item["entry_capabilities"]["preference_keys"]),
            )
            for item in registry["clients"]
        }
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"packaged ACP registry is invalid: {exc}") from exc
    if set(clients) != {"zed", "jetbrains"}:
        raise RuntimeError(f"packaged ACP registry contains unsupported clients: {list(clients)}")
    if len(clients) != len(set(clients)):
        raise RuntimeError("packaged ACP registry contains duplicate client IDs")
    if len(capabilities) != len(clients) or any(
        value.entries_key != "agent_servers"
        or value.managed_type not in {"", "custom"}
        or not {"command", "args", "env"} <= value.launch_keys
        or value.launch_keys - {"command", "args", "env", "type"}
        or not value.preference_keys.isdisjoint(value.launch_keys)
        for value in capabilities.values()
    ):
        raise RuntimeError("packaged ACP registry contains invalid editor entry capabilities")
    if not agents or any(
        not isinstance(agent_id, str)
        or not isinstance(command, str)
        or not command
        or not isinstance(args, tuple)
        or not all(isinstance(arg, str) for arg in args)
        for agent_id, (command, args) in agents.items()
    ):
        raise RuntimeError("packaged ACP registry contains an invalid agent entry point")
    if len(agents) != len(registry["agents"]):
        raise RuntimeError("packaged ACP registry contains duplicate agent IDs")
    return registry, clients, agents, capabilities


ACP_REGISTRY, ACP_CLIENT_IDS, ACP_AGENT_ENTRY_POINTS, ACP_CLIENT_ENTRY_CAPABILITIES = _load_catalog()
ACP_AGENT_IDS = tuple(sorted(ACP_AGENT_ENTRY_POINTS))
