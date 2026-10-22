# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Hermes health requires a runnable command read from the agent registration."""

import json
import hashlib
import os
from types import SimpleNamespace

import pytest
import yaml

from defenseclaw.commands import cmd_doctor
from defenseclaw.doctor_hooks import WindowsHookCheck, _HERMES_REQUIRED_HOOKS


@pytest.mark.skipif(os.name == "nt", reason="Unix shell hook")
def test_hermes_doctor_requires_registered_executable_probe(tmp_path, monkeypatch):
    data_dir = tmp_path / "dc"
    hooks_dir = data_dir / "hooks"
    hooks_dir.mkdir(parents=True)
    script = hooks_dir / "hermes-hook.sh"
    script.write_text("#!/bin/sh\nprintf 'defenseclaw-execution-probe-ok\\n'\n", encoding="utf-8")
    script.chmod(0o700)
    command = "'" + str(script) + "'"
    config = tmp_path / "hermes" / "config.yaml"
    config.parent.mkdir()
    hooks = {
        event: [{"command": command, "timeout": 30, **({"matcher": matcher} if matcher else {})}]
        for event, matcher in _HERMES_REQUIRED_HOOKS.items()
    }
    config.write_text(yaml.safe_dump({"hooks": hooks}), encoding="utf-8")
    lock_path = data_dir / "hook_contract_lock.json"

    def seal():
        lock_path.write_text(json.dumps({"connectors": {"hermes": {"hook_script_digests": {
            "hermes-hook.sh": hashlib.sha256(script.read_bytes()).hexdigest(),
        }, "locations": {
            "hook_config_paths": [str(config)], "hook_script_paths": [str(script)],
        }}}}), encoding="utf-8")

    seal()
    cfg = SimpleNamespace(data_dir=str(data_dir))
    monkeypatch.setattr(cmd_doctor, "_hermes_host_running", lambda: False)

    def check():
        result = cmd_doctor._DoctorResult()
        cmd_doctor._check_hook_health(cfg, "hermes", result)
        return result.checks[-1]

    assert check()["status"] == "pass"
    script.chmod(0o600)
    row = check()
    assert row["status"] == "fail", row
    assert "executable" in row["detail"]
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(0o700)
    seal()
    row = check()
    assert row["status"] == "fail", row
    assert "probe" in row["detail"]
    script.write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
    script.chmod(0o700)
    seal()
    row = check()
    assert row["status"] == "fail", row
    assert "probe" in row["detail"]


@pytest.mark.skipif(os.name == "nt", reason="Unix stub for the Windows probe helper")
def test_windows_hermes_probe_requires_active_runtime_response(tmp_path):
    target = tmp_path / "hook"
    check = WindowsHookCheck("healthy", "registered", '"hook" hook --connector hermes', str(target))
    target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    target.chmod(0o700)
    assert not cmd_doctor._hermes_windows_execution_probe(check).healthy
    target.write_text("#!/bin/sh\nprintf 'defenseclaw-execution-probe-ok\\n'\n", encoding="utf-8")
    assert cmd_doctor._hermes_windows_execution_probe(check).healthy
