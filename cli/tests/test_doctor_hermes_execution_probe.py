# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Hermes health requires a runnable command read from the agent registration."""

import contextlib
import hashlib
import json
import os
import time
import tracemalloc
import types
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


# r104 W5b: a probed launcher that exits after the proof must not leave what
# it started running, one more for each Doctor run.
def _process_gone(pid: int, wait: float = 3.0) -> bool:
    deadline = time.monotonic() + wait
    while True:
        if os.name == "nt":
            import ctypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
            kernel32.OpenProcess.restype = ctypes.c_void_p
            kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
            kernel32.WaitForSingleObject.restype = ctypes.c_uint32
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            handle = kernel32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
            if not handle:
                return True
            try:
                remaining = max(0, int((deadline - time.monotonic()) * 1000))
                return kernel32.WaitForSingleObject(handle, remaining) == 0
            finally:
                kernel32.CloseHandle(handle)
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        try:
            with open(f"/proc/{pid}/stat", encoding="utf-8") as stat:
                if stat.read().rsplit(")", 1)[1].split()[0] == "Z":
                    return True
        except (OSError, IndexError):
            pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)


def _kill_quietly(pid: int) -> None:
    import signal

    with contextlib.suppress(OSError):
        os.kill(pid, signal.SIGKILL)


def _read_pid(path) -> int:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with contextlib.suppress(OSError, ValueError):
            return int(path.read_text(encoding="utf-8").strip())
        time.sleep(0.02)
    raise AssertionError(f"probe never wrote {path}")


_DESCENDANT_CASES = {
    # body, timeout: what the hook leaves behind and how the probe ends
    "exits-child-holds-stdout": (_PROOF + 'sleep 60 & echo $! > "$PIDFILE"\nexit 0\n', 20.0),
    "exits-child-detached-from-stdout": (_PROOF + 'sleep 60 >/dev/null 2>&1 & echo $! > "$PIDFILE"\nexit 0\n', 20.0),
    "exits-grandchild": (_PROOF + '( sleep 60 & echo $! > "$PIDFILE" )\nexit 0\n', 20.0),
    "times-out": ('sleep 60 & echo $! > "$PIDFILE"\nwait\n', 0.5),
    "overflows": (_PROOF + 'sleep 60 & echo $! > "$PIDFILE"\nexec yes\n', 20.0),
}


def _descendant_stub(tmp_path, body: str):
    pid_file = tmp_path / "descendant.pid"
    target = _probe_stub(tmp_path, f"PIDFILE='{pid_file}'\n" + body)
    return target, pid_file


@pytest.mark.skipif(os.name == "nt", reason="Unix shell stub")
@pytest.mark.parametrize("case", list(_DESCENDANT_CASES), ids=list(_DESCENDANT_CASES))
def test_hermes_execution_probe_ends_what_the_hook_started(tmp_path, monkeypatch, case):
    body, timeout = _DESCENDANT_CASES[case]
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_TIMEOUT", timeout)
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_PIPE_WAIT", 0.5)
    target, pid_file = _descendant_stub(tmp_path, body)
    cmd_doctor._run_hermes_execution_probe([str(target)])
    descendant = _read_pid(pid_file)
    try:
        assert _process_gone(descendant), f"probe left descendant {descendant} running"
    finally:
        _kill_quietly(descendant)


class _ProxyModule(types.ModuleType):
    """``base`` with some attributes replaced, for one module's view only."""

    def __init__(self, base, **overrides):
        super().__init__(base.__name__)
        self._base = base
        self.__dict__.update(overrides)

    def __getattr__(self, name):
        return getattr(self._base, name)


class _EmulatedWindowsJob:
    """A kill-on-close job emulated by the probe's own POSIX session."""

    def __init__(self, pid: int, *, allow_breakaway: bool = True, fail: str = "") -> None:
        if fail == "create":
            raise OSError("CreateJobObjectW failed")
        self.pid = pid
        self.allow_breakaway = allow_breakaway
        self.fail = fail
        self.terminated = 0
        self.closed = False

    def terminate_sync(self, *, exit_code: int = 130, timeout: float = 2.0) -> bool:
        self.terminated += 1
        if self.fail == "terminate":
            raise OSError("TerminateJobObject failed")
        import signal

        with contextlib.suppress(ProcessLookupError):
            os.killpg(self.pid, signal.SIGKILL)
        return self.fail != "linger"

    def close(self) -> None:
        self.closed = True


def _emulate_windows_probe(monkeypatch, *, fail: str = ""):
    """Run the probe's Windows branch on POSIX; return the Popen kwargs and jobs."""
    import subprocess

    real_popen = subprocess.Popen
    launches: list[dict] = []
    jobs: list[_EmulatedWindowsJob] = []

    def popen(argv, **kwargs):
        launches.append(dict(kwargs))
        return real_popen(
            argv, stdin=kwargs["stdin"], stdout=kwargs["stdout"], stderr=kwargs["stderr"], start_new_session=True,
        )

    def job(pid, *, allow_breakaway=True):
        created = _EmulatedWindowsJob(pid, allow_breakaway=allow_breakaway, fail=fail)
        jobs.append(created)
        return created

    monkeypatch.setattr(cmd_doctor, "os", _ProxyModule(os, name="nt"))
    monkeypatch.setattr(cmd_doctor, "subprocess", _ProxyModule(subprocess, Popen=popen))
    monkeypatch.setattr("defenseclaw.tui.windows_process.WindowsJob", job)
    return launches, jobs


@pytest.mark.skipif(os.name == "nt", reason="emulates the Windows branch on a POSIX shell stub")
@pytest.mark.parametrize("case", list(_DESCENDANT_CASES), ids=list(_DESCENDANT_CASES))
def test_windows_hermes_doctor_probe_ends_its_job(tmp_path, monkeypatch, case):
    body, timeout = _DESCENDANT_CASES[case]
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_TIMEOUT", timeout)
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_PIPE_WAIT", 0.5)
    target, pid_file = _descendant_stub(tmp_path, body)
    launches, jobs = _emulate_windows_probe(monkeypatch)
    check = WindowsHookCheck("healthy", "registered", '"hook" hook --connector hermes', str(target))
    healthy = cmd_doctor._hermes_windows_execution_probe(check).healthy
    descendant = _read_pid(pid_file)
    try:
        assert _process_gone(descendant), f"Windows Doctor probe left descendant {descendant} running"
    finally:
        _kill_quietly(descendant)
    assert healthy is case.startswith("exits"), case
    (launch,) = launches
    assert launch["creationflags"] & 0x00000004, "the launcher must start suspended, before the job owns it"
    assert launch["creationflags"] & 0x08000000, "the probe must not open a console window"
    (job,) = jobs
    assert job.allow_breakaway is False
    assert job.terminated >= 1
    assert job.closed


@pytest.mark.skipif(os.name == "nt", reason="emulates the Windows branch on a POSIX shell stub")
@pytest.mark.parametrize("fail", ["create", "terminate", "linger"])
def test_windows_hermes_doctor_probe_fails_closed_without_job_cleanup(tmp_path, monkeypatch, fail):
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_PIPE_WAIT", 0.5)
    root_pid_file = tmp_path / "root.pid"
    target = _probe_stub(tmp_path, f"echo $$ > '{root_pid_file}'\n" + _PROOF + "exec sleep 60\n")
    _emulate_windows_probe(monkeypatch, fail=fail)
    start = time.monotonic()
    returncode, _ = cmd_doctor._run_hermes_execution_probe([str(target)])
    assert returncode is None, "a probe whose job could not be ended must not pass"
    assert time.monotonic() - start < 10
    if root_pid_file.exists():
        root = _read_pid(root_pid_file)
        try:
            assert _process_gone(root), f"uncontained probe root {root} still runs"
        finally:
            _kill_quietly(root)


@pytest.mark.skipif(os.name != "nt", reason="real Windows Job Object")
def test_windows_hermes_doctor_probe_ends_child_of_exited_launcher(tmp_path):
    import sys

    pid_file = tmp_path / "child.pid"
    code = (
        "import subprocess, sys\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(pid_file)!r}, 'w').write(str(child.pid))\n"
        "sys.stdout.write('defenseclaw-execution-probe-ok\\n')\n"
    )
    returncode, stdout = cmd_doctor._run_hermes_execution_probe([sys.executable, "-c", code])
    child = _read_pid(pid_file)
    assert _process_gone(child), f"Windows Doctor probe left child {child} running"
    assert returncode == 0
    assert stdout == b"defenseclaw-execution-probe-ok\n"
