# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``guardrail hilt`` finishes when the gateway is down (the TUI's ``h`` key runs it)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_guardrail
from defenseclaw.config import PerConnectorGuardrailConfig, default_config
from defenseclaw.context import AppContext
from defenseclaw.logger import CanonicalObservabilityUnavailableError

from tests.environment import isolated_home_env


@pytest.fixture
def app(tmp_path, monkeypatch):
    for key, value in isolated_home_env(tmp_path / "home").items():
        monkeypatch.setenv(key, value)
    cfg = default_config()
    cfg.data_dir = str(tmp_path / "dc")
    cfg.policy_dir = str(tmp_path / "dc" / "policies")
    cfg.guardrail.enabled = False  # no gateway restart
    cfg.save = MagicMock()
    context = AppContext()
    context.cfg = cfg
    context.logger = MagicMock()
    context.logger.log_action.side_effect = CanonicalObservabilityUnavailableError("gateway is down")
    return context


@pytest.mark.parametrize("connector", [None, "codex"])
def test_a_saved_change_exits_0_when_the_audit_event_cannot_be_written(app, connector) -> None:
    args = ["on", "--min-severity", "HIGH", "--yes"]
    if connector:
        app.cfg.guardrail.connectors = {
            "codex": PerConnectorGuardrailConfig(),
            "claudecode": PerConnectorGuardrailConfig(),
        }
        args += ["--connector", connector]
    result = CliRunner().invoke(cmd_guardrail.hilt_cmd, args, obj=app)
    assert result.exit_code == 0, result.output
    app.cfg.save.assert_called_once()
    assert "the audit event was not recorded" in result.output
    hilt = app.cfg.guardrail.effective_hilt(connector or "")
    assert (hilt.enabled, hilt.min_severity) == (True, "HIGH")


def test_fail_mode_exits_0_with_a_plain_note_when_the_gateway_is_stopped(app) -> None:
    """GAP-1250: after defenseclaw-gateway stop, fail-mode saved the value, then crashed."""
    result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["open", "--yes"], obj=app)
    assert result.exit_code == 0, result.output
    assert result.exception is None
    assert app.cfg.guardrail.hook_fail_mode == "open"
    # GAP-1718: one stopped-gateway note that also names the skipped audit event.
    assert result.output.count("gateway isn't running") == 1, result.output
    assert "the audit event was not recorded" in result.output


def test_bare_hilt_updates_alias_keys_and_the_protection_center_readback(app) -> None:
    from defenseclaw import policy_catalog
    from defenseclaw.config import HILTConfig
    from defenseclaw.tui.services.policy_state import PoliciesPanelModel

    gc = app.cfg.guardrail
    gc.connectors = {
        "claude-code": PerConnectorGuardrailConfig(hilt=HILTConfig(enabled=False)),
        "codex": PerConnectorGuardrailConfig(hilt=HILTConfig(enabled=False)),
    }
    before = set(gc.connectors)
    runner = CliRunner()
    result = runner.invoke(cmd_guardrail.hilt_cmd, ["on", "--min-severity", "MEDIUM", "--yes"], obj=app)
    assert result.exit_code == 0, result.output
    app.cfg.save.assert_called_once()
    assert set(gc.connectors) == before
    assert all(entry.hilt.enabled and entry.hilt.min_severity == "MEDIUM" for entry in gc.connectors.values())
    status = runner.invoke(cmd_guardrail.hilt_cmd, [], obj=app)
    assert status.exit_code == 0, status.output
    assert status.output.count("enabled=true min_severity=MEDIUM") == 2
    model = PoliciesPanelModel()
    model.set_config(app.cfg)
    model.apply_protection(policy_catalog.scope_postures(app.cfg))
    rows = {row[0]: row for row in model.data_table_rows(80)}
    assert rows["claudecode"][4] == rows["codex"][4] == "MEDIUM+"


@pytest.mark.parametrize("answer,yes,applied", [("\n", False, True), ("y\n", False, True), ("", False, False), ("", True, True)])
def test_hilt_scripts_can_answer_confirmation_or_skip_it(app, answer, yes, applied) -> None:
    args = ["on", "--min-severity", "HIGH"] + (["--yes"] if yes else [])
    result = CliRunner().invoke(cmd_guardrail.hilt_cmd, args, obj=app, input=answer)
    assert (result.exit_code == 0) == applied, result.output
    assert app.cfg.guardrail.hilt.enabled == applied
    assert app.cfg.save.call_count == int(applied)


@pytest.mark.parametrize("field,value,command", [
    ("hook_fail_mode", "closed", cmd_guardrail.fail_mode_cmd),
    ("block_message", "marker policy refused", cmd_guardrail.block_message_cmd),
])
def test_bare_policy_writes_resolve_the_same_alias_keys(app, field, value, command) -> None:
    gc = app.cfg.guardrail
    gc.connectors = {
        key: PerConnectorGuardrailConfig(hook_fail_mode="open", block_message="prior message")
        for key in ("claude-code", "codex")
    }
    result = CliRunner().invoke(command, [value, "--no-restart", "--yes"], obj=app)
    assert result.exit_code == 0, result.output
    app.cfg.save.assert_called_once()
    assert set(gc.connectors) == {"claude-code", "codex"}
    assert all(getattr(entry, field) == value for entry in gc.connectors.values())
