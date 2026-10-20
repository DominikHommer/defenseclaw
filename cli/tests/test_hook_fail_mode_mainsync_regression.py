# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Main-sync regression (rel-1-0-3 MAINSYNC): the Python fail-mode resolver
keeps unset, empty and invalid values closed; only an explicit per-user open
opens, and a managed standalone config is closed whatever it says."""

from __future__ import annotations

import pytest
from defenseclaw import config_writer
from defenseclaw.config import Config, GuardrailConfig, PerConnectorGuardrailConfig

CONNECTORS = ["amp", "antigravity", "claudecode", "codex", "copilot", "devin", "hermes", "kiro", "opencode", "openhands"]


@pytest.mark.parametrize("connector", CONNECTORS)
@pytest.mark.parametrize("mode", ["observe", "action"])
@pytest.mark.parametrize(
    ("global_mode", "connector_mode", "want"),
    [
        ("", "", "closed"),
        ("  ", "", "closed"),
        ("opne", "", "closed"),
        ("", "opne", "closed"),
        ("closed", "", "closed"),
        ("open", "closed", "closed"),
        ("open", "", "open"),
        ("", "open", "open"),
        ("", " Open ", "open"),
    ],
)
def test_per_user_fail_mode_opens_only_on_explicit_open(connector, mode, global_mode, connector_mode, want):
    guardrail = GuardrailConfig(mode=mode, hook_fail_mode=global_mode)
    if connector_mode:
        guardrail.connectors = {connector: PerConnectorGuardrailConfig(hook_fail_mode=connector_mode)}
    assert guardrail.effective_hook_fail_mode(connector) == want


@pytest.mark.parametrize("connector", [*CONNECTORS, "cursor"])
@pytest.mark.parametrize("mode", ["observe", "action"])
def test_managed_standalone_fail_mode_is_always_closed(monkeypatch, connector, mode):
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    monkeypatch.delenv("DEFENSECLAW_ENTERPRISE_PROFILE", raising=False)
    monkeypatch.setattr(config_writer, "machine_managed_standalone", lambda: False)
    cfg = Config(
        deployment_mode="managed_enterprise",
        enterprise_profile="standalone",
        guardrail=GuardrailConfig(
            mode=mode,
            hook_fail_mode="open",
            connectors={connector: PerConnectorGuardrailConfig(hook_fail_mode="open")},
        ),
    )
    assert cfg.managed_hooks_fail_closed()
    assert cfg.guardrail.effective_hook_fail_mode(connector) == "closed"
