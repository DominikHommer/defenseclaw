# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Hook registration and command checks against the files Setup writes.

fixtures/hook_layouts/hook_layouts.json holds the agent config file each
Bedrock connector's Go Setup writes on a POSIX host (Claude Code, Codex,
Copilot, Hermes, OpenCode), the same files with the hook entries removed but
other DefenseClaw text left (GAP-1311), and the Windows launcher commands.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw import hook_integrity
from defenseclaw.hook_integrity import hook_command_problems, hook_registration_problems

_LAYOUTS = json.loads(
    (Path(__file__).resolve().parent / "fixtures" / "hook_layouts" / "hook_layouts.json").read_text(encoding="utf-8")
)
_CONNECTORS = ["claudecode", "codex", "copilot", "hermes", "opencode"]
_REMOVABLE = ["claudecode", "codex", "copilot", "hermes"]

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX hook layouts")


def _install(tmp_path: Path, connector: str, document: str, *, data_dir: Path | None = None, extra: list[Path] = ()):
    home = tmp_path / "home"
    data_dir = data_dir or home / ".defenseclaw"
    data_dir.mkdir(parents=True, exist_ok=True)
    config = home / _LAYOUTS[connector]["file"]
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(document.replace("{data_dir}", str(data_dir)).replace("{home}", str(home)), encoding="utf-8")
    paths = [str(config), *map(str, extra)]
    lock = {"version": 2, "connectors": {connector: {"locations": {"hook_config_paths": paths}}}}
    (data_dir / "hook_contract_lock.json").write_text(json.dumps(lock), encoding="utf-8")
    return SimpleNamespace(data_dir=str(data_dir), deployment_mode=""), config


@posix_only
@pytest.mark.parametrize("connector", _CONNECTORS)
def test_the_file_setup_writes_is_registered(tmp_path, monkeypatch, connector):
    monkeypatch.chdir(tmp_path)
    cfg, _ = _install(tmp_path, connector, _LAYOUTS[connector]["healthy"])
    assert hook_registration_problems(cfg, connector) == []
    assert hook_command_problems(cfg, connector) == []


@posix_only
@pytest.mark.parametrize("connector", _REMOVABLE)
def test_removed_hooks_are_reported_though_other_defenseclaw_text_stays(tmp_path, monkeypatch, connector):
    # GAP-1311: the Codex [otel] x-defenseclaw-source headers and notify
    # bridge, the Claude Code OTEL env and an MCP server entry name DefenseClaw
    # but register no hook.
    monkeypatch.chdir(tmp_path)
    removed = _LAYOUTS[connector]["removed"]
    assert "defenseclaw" in removed.lower()
    cfg, config = _install(tmp_path, connector, removed)
    assert hook_registration_problems(cfg, connector) == [f"no DefenseClaw hooks are registered in {config}"]


@posix_only
def test_json_settings_without_a_hooks_key_are_not_registered(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    document = json.dumps({"statusLine": {"command": "{data_dir}/hooks/claude-code-hook.sh"}})
    cfg, config = _install(tmp_path, "claudecode", document)
    assert hook_registration_problems(cfg, "claudecode") == [f"no DefenseClaw hooks are registered in {config}"]


@posix_only
def test_a_hook_that_is_not_defenseclaws_does_not_count(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    document = json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"command": "/usr/local/bin/defenseclaw-audit.sh"}]}]}})
    cfg, config = _install(tmp_path, "claudecode", document)
    assert hook_registration_problems(cfg, "claudecode") == [f"no DefenseClaw hooks are registered in {config}"]


@posix_only
def test_every_recorded_path_is_checked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    second = tmp_path / "home" / ".claude" / "settings.local.json"
    second.parent.mkdir(parents=True)
    second.write_text(_LAYOUTS["claudecode"]["removed"], encoding="utf-8")
    cfg, _ = _install(tmp_path, "claudecode", _LAYOUTS["claudecode"]["healthy"], extra=[second])
    assert hook_registration_problems(cfg, "claudecode") == [f"no DefenseClaw hooks are registered in {second}"]


@posix_only
def test_copilot_bash_hook_command_with_an_unquoted_space_cannot_run(tmp_path, monkeypatch):
    # GAP-1385: Copilot registers `bash` entries, which the command check skipped.
    monkeypatch.chdir(tmp_path)
    data_dir = tmp_path / "dc user" / ".defenseclaw"
    script = data_dir / "hooks" / "copilot-hook.sh"
    good = json.dumps({"version": 1, "hooks": {"preToolUse": [{"type": "command", "bash": f"'{script}' --event 'preToolUse'"}]}})
    cfg, config = _install(tmp_path, "copilot", good, data_dir=data_dir)
    assert hook_registration_problems(cfg, "copilot") == []
    config.write_text(
        json.dumps({"version": 1, "hooks": {"preToolUse": [{"type": "command", "bash": f"{script} --event preToolUse"}]}}),
        encoding="utf-8",
    )
    problems = hook_command_problems(cfg, "copilot")
    assert problems and "cannot run" in problems[0] and str(config) in problems[0]
    assert hook_registration_problems(cfg, "copilot") == problems


@posix_only
def test_hermes_yaml_hook_command_with_an_unquoted_space_cannot_run(tmp_path, monkeypatch):
    # GAP-1467: the Hermes config.yaml was parsed as JSON, so its commands went unchecked.
    monkeypatch.chdir(tmp_path)
    data_dir = tmp_path / "dc user" / ".defenseclaw"
    script = data_dir / "hooks" / "hermes-hook.sh"
    cfg, config = _install(tmp_path, "hermes", f"hooks:\n  pre_tool_call:\n    - command: \"'{script}'\"\n", data_dir=data_dir)
    assert hook_registration_problems(cfg, "hermes") == []
    config.write_text(f"hooks:\n  pre_tool_call:\n    - command: {script}\n", encoding="utf-8")
    problems = hook_command_problems(cfg, "hermes")
    assert problems and "cannot run" in problems[0] and str(config) in problems[0]


def _windows_document(connector: str, command: str) -> str:
    if connector == "codex":
        return (
            "[hooks]\n[[hooks.PreToolUse]]\nmatcher = '*'\n\n[[hooks.PreToolUse.hooks]]\n"
            f"command = '{command}'\ncommand_windows = '{command}'\ntype = 'command'\n"
            "\n[otel.exporter.otlp-http.headers]\nx-defenseclaw-source = 'codex'\n"
        )
    if connector == "copilot":
        return json.dumps({"version": 1, "hooks": {"preToolUse": [{"type": "command", "powershell": command}]}})
    if connector == "hermes":
        return f"hooks:\n  pre_tool_call:\n    - command: '{command}'\n"
    return json.dumps({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": command}]}]}})


@pytest.mark.parametrize("connector", ["claudecode", "codex", "copilot", "hermes"])
def test_windows_launcher_registrations_are_registered(tmp_path, monkeypatch, connector):
    # Per-user Windows registers the native launcher inside a PowerShell
    # -EncodedCommand; the plain command text never names DefenseClaw.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(hook_integrity, "_is_windows", lambda: True)
    command = _LAYOUTS["windows_commands"][connector]
    assert "defenseclaw" not in command.lower()
    cfg, config = _install(tmp_path, connector, _windows_document(connector, command))
    assert hook_registration_problems(cfg, connector) == []

    removed = {"codex": "[otel.exporter.otlp-http.headers]\nx-defenseclaw-source = 'codex'\n"}.get(
        connector, json.dumps({"hooks": {}, "env": {"OTEL_RESOURCE_ATTRIBUTES": "defenseclaw.connector=x"}})
    )
    if connector == "hermes":
        removed = "mcp_servers:\n  defenseclaw:\n    command: defenseclaw\n"
    config.write_text(removed, encoding="utf-8")
    assert hook_registration_problems(cfg, connector) == [f"no DefenseClaw hooks are registered in {config}"]
