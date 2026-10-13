# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Doctor rows for what a rollback leaves in the agent settings (1.0.2)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_doctor import _DoctorResult

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX hook scripts")


def _settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, data_dir: Path) -> Path:
    claude = tmp_path / "claude"
    claude.mkdir()
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(claude))
    script = data_dir / "hooks" / "claude-code-hook.sh"
    settings = {
        "hooks": {
            "UserPromptSubmit": [
                {"hooks": [{"type": "command", "command": f"{script} || {{ rc=$?; exit 2; }}"}]},
                {"hooks": [{"type": "command", "command": "/opt/operator/prompt-check.sh"}]},
            ]
        }
    }
    path = claude / "settings.json"
    path.write_text(json.dumps(settings), encoding="utf-8")
    return path


def _cfg(data_dir: Path, *active: str) -> SimpleNamespace:
    return SimpleNamespace(data_dir=str(data_dir), active_connectors=lambda: list(active))


def test_doctor_fails_on_hook_entries_of_a_connector_a_rollback_left(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # rel-1-0-1:GAP-0009: after a rollback Claude Code ran a DefenseClaw hook
    # script the restored data dir does not have and blocked every prompt.
    data_dir = tmp_path / "dc"
    path = _settings(tmp_path, monkeypatch, data_dir)
    r = _DoctorResult()

    cmd_doctor._check_orphaned_hook_entries(_cfg(data_dir, "codex"), "codex", r)

    (check,) = r.checks
    assert check["status"] == "fail" and check["label"] == "Orphaned hook entries [claudecode]"
    assert f"{path} has DefenseClaw hook entries for claudecode, which is not configured" in check["detail"]
    assert "does not exist" in check["detail"]
    assert check["remediation"] == "defenseclaw setup remove claudecode"


def test_doctor_names_entries_of_an_unconfigured_connector_whose_script_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "dc"
    _settings(tmp_path, monkeypatch, data_dir)
    (data_dir / "hooks").mkdir(parents=True)
    (data_dir / "hooks" / "claude-code-hook.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    r = _DoctorResult()

    cmd_doctor._check_orphaned_hook_entries(_cfg(data_dir, "codex"), "codex", r)

    (check,) = r.checks
    assert check["status"] == "warn" and check["remediation"] == "defenseclaw setup remove claudecode"


def test_doctor_is_silent_for_a_configured_connector_and_for_other_installs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "dc"
    _settings(tmp_path, monkeypatch, data_dir)
    r = _DoctorResult()
    cmd_doctor._check_orphaned_hook_entries(_cfg(data_dir, "claudecode"), "claudecode", r)
    # Entries that run another data dir's scripts are not this install's.
    cmd_doctor._check_orphaned_hook_entries(_cfg(tmp_path / "other"), "", r)
    assert r.checks == []
