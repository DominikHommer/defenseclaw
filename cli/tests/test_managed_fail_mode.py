# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""A managed deployment outside Secure Client fails closed (rel-1-0-3 GAP-0037).

Mirrors internal/config/managed_fail_mode_test.go: every connector in every
guardrail mode resolves closed there, and the upstream fail-open connectors
(Copilot CLI, Antigravity, Hermes) are reported closed too; Secure Client and
per-user installs keep the configured values.
"""

from __future__ import annotations

import pytest
from defenseclaw import config_writer
from defenseclaw.config import Config, GuardrailConfig, PerConnectorGuardrailConfig
from defenseclaw.fail_mode import upstream_fail_open

CONNECTORS = ("amp", "antigravity", "copilot", "cursor", "hermes", "kiro", "opencode")


def _config(deployment_mode: str, profile: str) -> Config:
    cfg = Config(
        deployment_mode=deployment_mode,
        enterprise_profile=profile,
        guardrail=GuardrailConfig(
            mode="observe",
            hook_fail_mode="open",
            connectors={
                "amp": PerConnectorGuardrailConfig(hook_fail_mode="open"),
                "cursor": PerConnectorGuardrailConfig(hook_fail_mode="open"),
            },
        ),
    )
    return cfg


@pytest.fixture(autouse=True)
def _no_host_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    monkeypatch.delenv("DEFENSECLAW_ENTERPRISE_PROFILE", raising=False)
    monkeypatch.setattr(config_writer, "machine_managed_standalone", lambda: False)


def test_standalone_resolves_closed_for_every_connector() -> None:
    cfg = _config("managed_enterprise", "standalone")
    assert cfg.managed_hooks_fail_closed()
    for name in CONNECTORS:
        assert cfg.guardrail.effective_hook_fail_mode(name) == "closed", name
        assert not upstream_fail_open(cfg, name), name


@pytest.mark.parametrize(
    ("deployment_mode", "profile"),
    [("managed_enterprise", "secure_client"), ("", "")],
)
def test_secure_client_and_per_user_keep_configured_values(deployment_mode: str, profile: str) -> None:
    cfg = _config(deployment_mode, profile)
    assert not cfg.managed_hooks_fail_closed()
    for name in ("amp", "cursor", "kiro"):
        assert cfg.guardrail.effective_hook_fail_mode(name) == "open", name
    for name in ("antigravity", "copilot"):
        assert upstream_fail_open(cfg, name), name
    # The per-user Hermes hook blocks its own failures on every OS
    # (GAP-0150, GAP-0269); only Secure Client keeps Hermes open.
    assert upstream_fail_open(cfg, "hermes") is (deployment_mode == "managed_enterprise")


def test_machine_marker_makes_any_managed_config_standalone(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_writer, "machine_managed_standalone", lambda: True)
    cfg = _config("managed_enterprise", "secure_client")
    assert cfg.managed_hooks_fail_closed()
    assert cfg.guardrail.effective_hook_fail_mode("kiro") == "closed"
