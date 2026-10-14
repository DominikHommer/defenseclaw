# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""A connector staged for an agent that is not installed is not RUNNING (GAP-0513).

`defenseclaw setup copilot --yes` on a host without the Copilot CLI warns and
writes the hooks for a later install. The gateway then registers the
connector, so `status` showed "Agents: 1 active" and "GitHub Copilot CLI ...
RUNNING" while doctor failed "Connector compatibility: copilot (agent
installation unavailable)". Status now uses doctor's rule.
"""

from __future__ import annotations

import contextlib
import io
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from defenseclaw import doctor_health
from defenseclaw.commands import cmd_status
from defenseclaw.config import AIDiscoveryConfig, ApplicationProtectionConfig
from defenseclaw.inventory import agent_discovery


def _cfg(actives):
    cfg = MagicMock()
    cfg.active_connectors.return_value = list(actives)
    cfg.guardrail.effective_mode.side_effect = lambda c: "observe"
    cfg.guardrail.effective_enabled.side_effect = lambda c: True
    cfg.application_protection = ApplicationProtectionConfig()
    cfg.ai_discovery = AIDiscoveryConfig()
    cfg.data_dir = "/nonexistent/defenseclaw-data"
    return cfg


@pytest.fixture
def copilot_not_installed(monkeypatch):
    """Discovery evidence finds no Copilot CLI; Codex is installed."""
    discovery = SimpleNamespace(
        partial=False,
        agents={
            "copilot": SimpleNamespace(installed=False, version=""),
            "codex": SimpleNamespace(installed=True, version="codex-cli 0.142.0"),
        },
    )
    monkeypatch.setattr(doctor_health, "read_cached_discovery", lambda data_dir: discovery)
    on_path: dict[str, str] = {}
    monkeypatch.setattr(agent_discovery, "binary_on_path", lambda connector: on_path.get(connector, ""))
    monkeypatch.setattr(cmd_status, "_hook_runtime_degraded_suffix", lambda cfg, connector: "")
    return on_path


def _render(cfg, health=None) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cmd_status._print_agents(cfg, health=health)
    return buf.getvalue()


def _row(out: str, label: str) -> str:
    return next(line for line in out.splitlines() if label in line)


def test_doctor_rule_names_the_missing_agent(copilot_not_installed):
    assert doctor_health.connector_agent_missing("/x", "copilot") is True
    assert doctor_health.connector_agent_missing("/x", "codex") is False
    # Installed after the last discovery scan: not missing (GAP-0052).
    copilot_not_installed["copilot"] = "/usr/local/bin/copilot"
    assert doctor_health.connector_agent_missing("/x", "copilot") is False


def test_no_discovery_evidence_is_no_proof(monkeypatch):
    monkeypatch.setattr(doctor_health, "read_cached_discovery", lambda data_dir: None)
    assert doctor_health.connector_agent_missing("/x", "copilot") is False


def test_status_does_not_call_a_staged_connector_running(copilot_not_installed):
    cfg = _cfg(["codex", "copilot"])
    health = {"connectors": [{"name": "codex", "state": "running"}, {"name": "copilot", "state": "running"}]}
    out = _render(cfg, health)
    copilot = _row(out, "GitHub Copilot CLI (copilot)")
    assert "RUNNING" not in copilot and "OFF" in copilot
    assert "is not installed" in out and "defenseclaw agent discover --refresh" in out
    assert "RUNNING" in _row(out, "Codex (codex)")
    assert "1 active, 1 not running" in _row(out, "Agents")


def test_status_without_the_gateway_names_the_missing_agent(copilot_not_installed):
    out = _render(_cfg(["copilot"]))
    assert "OFF" in _row(out, "GitHub Copilot CLI (copilot)")
    assert "0 active, 1 not running" in _row(out, "Agents")


def test_an_installed_agent_still_runs(copilot_not_installed):
    copilot_not_installed["copilot"] = "/usr/local/bin/copilot"
    out = _render(_cfg(["copilot"]), {"connectors": [{"name": "copilot", "state": "running"}]})
    assert "RUNNING" in _row(out, "GitHub Copilot CLI (copilot)")
    assert "1 active" in _row(out, "Agents")


def test_status_json_agrees(copilot_not_installed):
    rows = {row["name"]: row for row in cmd_status._connector_roster(_cfg(["codex", "copilot"]))}
    assert rows["copilot"]["state"] == "off"
    assert "is not installed" in rows["copilot"]["runtime_detail"]
    assert "state" not in rows["codex"]
