# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Running OpenShell sandboxes stop ``uninstall`` and ``reset`` before any change (GAP-0368)."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from unittest.mock import patch

import click
import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_uninstall
from defenseclaw.commands import windows_native_uninstall as native

_LISTED = {
    "sandboxes": [
        {"name": "cdx-enforce", "workdir_mode": "copy", "phase": "ready"},
        {"name": "myapp-claude", "workdir_mode": "mount", "phase": "ready"},
        {"name": "old-copy", "workdir_mode": "copy", "phase": "stopped"},
    ]
}


def _completed(returncode=0, stdout="", stderr=""):
    return type("Completed", (), {"returncode": returncode, "stdout": stdout, "stderr": stderr})()


@pytest.fixture()
def gateway(tmp_path: Path) -> str:
    path = tmp_path / "defenseclaw-gateway"
    path.write_text("#!/bin/sh\n")
    return str(path)


def _invoke(command, args, plan, listed):
    with (
        patch.object(native, "prepare_native_windows_uninstall", return_value=None),
        patch.object(cmd_uninstall, "_build_plan", return_value=plan),
        patch.object(cmd_uninstall, "_render_plan"),
        patch("subprocess.run", return_value=listed) as run,
        patch.object(cmd_uninstall, "_execute_plan") as execute,
    ):
        result = CliRunner().invoke(command, args)
    return result, execute, run


def _one_line(text: str) -> str:
    return " ".join(text.split())


def test_running_sandboxes_refuse_the_uninstall_before_any_change(gateway: str) -> None:
    plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=gateway)
    result, execute, run = _invoke(
        cmd_uninstall.uninstall_cmd, ["--all", "--binaries", "--yes"], plan, _completed(stdout=json.dumps(_LISTED))
    )
    assert result.exit_code == 1, result.output
    execute.assert_not_called()
    assert run.call_args.args[0] == [gateway, "sandbox", "list", "--output", "json"]
    out = _one_line(result.output)
    assert "2 OpenShell sandboxes run for this account (cdx-enforce, myapp-claude)" in out
    assert "nothing was changed" in out
    assert "`defenseclaw sandbox pull cdx-enforce --branch` keeps its work on branch dc/cdx-enforce" in out
    assert "`defenseclaw sandbox stop cdx-enforce`" in out
    assert "`defenseclaw sandbox review myapp-claude`" in out
    assert "`defenseclaw sandbox stop myapp-claude`" in out
    assert "add --stop-sandboxes" in out
    # A stopped sandbox does not refuse the run.
    assert "old-copy" not in out


def test_stop_sandboxes_lets_the_teardown_stop_them(gateway: str) -> None:
    plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=gateway)
    result, execute, _ = _invoke(
        cmd_uninstall.uninstall_cmd,
        ["--all", "--binaries", "--stop-sandboxes", "--yes"],
        plan,
        _completed(stdout=json.dumps(_LISTED)),
    )
    assert result.exit_code == 0, result.output
    execute.assert_called_once()
    ran = execute.call_args.args[0]
    assert ran.stop_sandboxes
    assert ran.running_sandboxes == (("cdx-enforce", "copy"), ("myapp-claude", "mount"))
    assert ran.live_sandboxes == ("myapp-claude",)


def test_dry_run_says_a_real_run_would_stop(gateway: str) -> None:
    plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=gateway)
    result, execute, _ = _invoke(
        cmd_uninstall.uninstall_cmd, ["--dry-run"], plan, _completed(stdout=json.dumps(_LISTED))
    )
    assert result.exit_code == 0, result.output
    execute.assert_not_called()
    out = _one_line(result.output)
    assert "a real run would stop before any change" in out
    assert "(cdx-enforce, myapp-claude)" in out


@pytest.mark.parametrize(
    "listed",
    [
        # Only stopped sandboxes: nothing runs.
        _completed(stdout=json.dumps({"sandboxes": [_LISTED["sandboxes"][2]]})),
        # The daemon cannot say: the teardown runs as before.
        _completed(returncode=1, stderr="the sandbox daemon is not running"),
    ],
)
def test_no_running_sandbox_does_not_refuse(gateway: str, listed) -> None:
    plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=gateway)
    result, execute, _ = _invoke(cmd_uninstall.uninstall_cmd, ["--yes"], plan, listed)
    assert result.exit_code == 0, result.output
    execute.assert_called_once()
    assert execute.call_args.args[0].running_sandboxes == ()


def test_skipped_teardown_does_not_list_or_refuse(gateway: str) -> None:
    plan = cmd_uninstall.UninstallPlan(sandbox_teardown=False, sandbox_teardown_skipped=True, gateway_path=gateway)
    result, execute, run = _invoke(
        cmd_uninstall.uninstall_cmd,
        ["--skip-sandbox-teardown", "--yes"],
        plan,
        _completed(stdout=json.dumps(_LISTED)),
    )
    assert result.exit_code == 0, result.output
    execute.assert_called_once()
    run.assert_not_called()


def test_reset_refuses_running_sandboxes_too(gateway: str) -> None:
    plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=gateway)
    result, execute, _ = _invoke(cmd_uninstall.reset_cmd, ["--yes"], plan, _completed(stdout=json.dumps(_LISTED)))
    assert result.exit_code == 1, result.output
    execute.assert_not_called()
    assert "add --stop-sandboxes" in _one_line(result.output)
    result, execute, _ = _invoke(
        cmd_uninstall.reset_cmd, ["--stop-sandboxes", "--yes"], plan, _completed(stdout=json.dumps(_LISTED))
    )
    assert result.exit_code == 0, result.output
    execute.assert_called_once()


def test_plan_validation_refuses_running_sandboxes() -> None:
    running = (("cdx-enforce", "copy"),)
    with pytest.raises(click.ClickException, match="1 OpenShell sandbox runs for this account"):
        cmd_uninstall._validate_plan(cmd_uninstall.UninstallPlan(sandbox_teardown=True, running_sandboxes=running))
    cmd_uninstall._validate_plan(
        cmd_uninstall.UninstallPlan(sandbox_teardown=True, running_sandboxes=running, stop_sandboxes=True)
    )


def test_plan_names_the_running_sandboxes() -> None:
    running = (("cdx-enforce", "copy"),)
    for stop, want in (
        (
            False,
            "running sandboxes (cdx-enforce) stop this run before any change: stop them first, or add --stop-sandboxes",
        ),
        (True, "running sandboxes (cdx-enforce) are stopped and deleted (--stop-sandboxes)"),
    ):
        plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, running_sandboxes=running, stop_sandboxes=stop)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cmd_uninstall._render_plan(plan, dry_run=True)
        assert want in _one_line(buf.getvalue())


def test_teardown_says_it_is_running_before_it_waits(gateway: str) -> None:
    plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=gateway)
    buf = io.StringIO()
    seen = []

    def fake_run(argv, **_):
        if argv[-1] == "--help":
            return _completed(stdout="Flags:\n  --keep-images\n")
        seen.append(buf.getvalue())
        return _completed(stdout="✓ teardown complete\n")

    with patch("subprocess.run", side_effect=fake_run), contextlib.redirect_stdout(buf):
        cmd_uninstall._sandbox_teardown(plan)
    # Printed before the teardown, which shows its own output only at the end.
    assert "tearing down DefenseClaw's OpenShell sandboxes" in seen[0]
