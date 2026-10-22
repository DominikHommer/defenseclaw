# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Hermes health requires a runnable command read from the agent registration."""

import hashlib
import json
import os
import time
import tracemalloc
from types import SimpleNamespace

import pytest
import yaml
from defenseclaw.commands import cmd_doctor
from defenseclaw.doctor_hooks import _HERMES_REQUIRED_HOOKS, WindowsHookCheck


def _registered_unix_hermes(tmp_path, monkeypatch):
    """Register a sealed Unix Hermes hook; return it and a reseal-and-check call."""
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

    def check(*, reseal: bool = True):
        if reseal:
            seal()
        result = cmd_doctor._DoctorResult()
        cmd_doctor._check_hook_health(cfg, "hermes", result)
        return result.checks[-1]

    return script, check


@pytest.mark.skipif(os.name == "nt", reason="Unix shell hook")
def test_hermes_doctor_requires_registered_executable_probe(tmp_path, monkeypatch):
    script, check = _registered_unix_hermes(tmp_path, monkeypatch)
    assert check()["status"] == "pass"
    script.chmod(0o600)
    row = check(reseal=False)
    assert row["status"] == "fail", row
    assert "executable" in row["detail"]
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(0o700)
    row = check()
    assert row["status"] == "fail", row
    assert "probe" in row["detail"]
    script.write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
    script.chmod(0o700)
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


_PROOF = "printf 'defenseclaw-execution-probe-ok\\n'\n"
_OVERSIZED_OUTPUTS = {
    "proof-then-64MiB": _PROOF + "head -c 67108864 /dev/zero\n",
    "64MiB-then-proof": "head -c 67108864 /dev/zero\n" + _PROOF,
    "endless-stream": _PROOF + "exec yes\n",
}


def _probe_stub(tmp_path, body: str):
    target = tmp_path / "hook"
    target.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    target.chmod(0o700)
    return target


@pytest.mark.skipif(os.name == "nt", reason="Unix shell stub")
@pytest.mark.parametrize("body", list(_OVERSIZED_OUTPUTS.values()), ids=list(_OVERSIZED_OUTPUTS))
def test_hermes_execution_probe_caps_captured_output(tmp_path, monkeypatch, body):
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_TIMEOUT", 20.0)
    target = _probe_stub(tmp_path, body)
    check = WindowsHookCheck("healthy", "registered", '"hook" hook --connector hermes', str(target))
    tracemalloc.start()
    start = time.monotonic()
    try:
        healthy = cmd_doctor._hermes_windows_execution_probe(check).healthy
        returncode, stdout = cmd_doctor._run_hermes_execution_probe([str(target)])
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert not healthy
    assert returncode is None
    assert len(stdout) <= len(b"defenseclaw-execution-probe-ok\n")
    assert peak < 4 << 20, f"Doctor kept {peak} bytes of probe output"
    assert time.monotonic() - start < 10, "an output overflow must end the probe before its timeout"


@pytest.mark.skipif(os.name == "nt", reason="Unix shell stub")
def test_hermes_unix_doctor_probe_caps_registered_hook_output(tmp_path, monkeypatch):
    script, check = _registered_unix_hermes(tmp_path, monkeypatch)
    script.write_text("#!/bin/sh\n" + _OVERSIZED_OUTPUTS["proof-then-64MiB"], encoding="utf-8")
    script.chmod(0o700)
    tracemalloc.start()
    try:
        row = check()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert row["status"] == "fail", row
    assert "probe" in row["detail"]
    assert peak < 16 << 20, f"Doctor kept {peak} bytes of probe output"


@pytest.mark.skipif(os.name == "nt", reason="Unix shell stub")
@pytest.mark.parametrize(
    ("body", "timeout", "proved"),
    [
        (_PROOF + "sleep 20 &\nexit 0\n", 20.0, None),
        ("sleep 20 &\nsleep 20\n", 0.3, False),
        ("trap '' TERM\n" + _PROOF + "sleep 20 &\nsleep 20\n", 0.3, False),
    ],
    ids=["exits-descendant-holds-stdout", "hangs-descendant-holds-stdout", "hangs-after-proof"],
)
def test_hermes_execution_probe_bounds_inherited_stdout(tmp_path, monkeypatch, body, timeout, proved):
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_TIMEOUT", timeout)
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_PIPE_WAIT", 0.5)
    target = _probe_stub(tmp_path, body)
    check = WindowsHookCheck("healthy", "registered", '"hook" hook --connector hermes', str(target))
    start = time.monotonic()
    healthy = cmd_doctor._hermes_windows_execution_probe(check).healthy
    assert time.monotonic() - start < 2, "the probe waited on stdout a descendant inherited"
    if proved is not None:
        assert healthy is proved
