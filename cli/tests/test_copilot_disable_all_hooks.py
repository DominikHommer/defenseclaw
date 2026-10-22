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

"""An agent setting that turns its hooks off fails every guarded-or-not check (rel-1-0-4 GAP-0580).

With ``disableAllHooks: true`` in the per-user Copilot settings, Copilot runs
none of its hooks, so no tool call reaches DefenseClaw. The doctor Copilot row
failed, but ``status``, the first-run "Connector runtime" read-back (also used
after guardrail changes) and the ``guardrail status`` posture rows read
:func:`hook_integrity.agent_hook_switch_problems`, which had no Copilot branch,
and showed the connector as guarded. The Claude Code and Codex switches were
reported there only as a warning.

Each case starts from the files Setup writes
(internal/gateway/connector/testdata/hook_registration_every_connector.json).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from defenseclaw import bootstrap, hook_integrity
from defenseclaw.commands import cmd_doctor, cmd_status

from tests.test_hook_registration_every_connector import _CASES, _case_id, _install

_COPILOT = [case for case in _CASES if case["connector"] == "copilot"]

# Every layer of the Copilot settings cascade (connector_paths.copilot_settings_paths).
_USER_LAYERS = ["{home}/.copilot/config.json", "{home}/.copilot/settings.json"]
_REPOSITORY_LAYERS = [
    "{home}/ws/.claude/settings.json",
    "{home}/ws/.github/copilot/settings.json",
    "{home}/ws/.claude/settings.local.json",
    "{home}/ws/.github/copilot/settings.local.json",
]


def _layers(case: dict[str, Any]) -> list[str]:
    return _USER_LAYERS + (_REPOSITORY_LAYERS if case["scope"] == "workspace" else [])


_SWITCH_CASES = [
    pytest.param(case, layer, platform, id=f"{_case_id(case)}-{Path(layer).parent.name}-{Path(layer).name}-{platform}")
    for case in _COPILOT
    for layer in _layers(case)
    for platform in ("posix", "windows")
]


def _copilot(tmp_path: Path, monkeypatch, case: dict[str, Any], platform: str = "posix"):
    monkeypatch.delenv("COPILOT_HOME", raising=False)
    if platform == "windows":
        monkeypatch.setattr(hook_integrity, "_is_windows", lambda: True)
        monkeypatch.setattr(hook_integrity, "hook_launcher_problems", lambda cfg, connector: [])
    return _install(tmp_path, monkeypatch, case)


def _write(tmp_path: Path, layer: str, content: str) -> Path:
    path = Path(layer.replace("{home}", str(tmp_path / "home")))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _readiness(cfg, connector: str):
    return bootstrap._connector_runtime_readiness(cfg, connector)


def _doctor_rows(cfg, monkeypatch) -> list[dict[str, Any]]:
    monkeypatch.setattr(cmd_doctor, "_opencode_managed_plugin_drift", lambda *_a, **_k: "")
    r = cmd_doctor._DoctorResult(passive=True, quiet=True)
    cmd_doctor._check_connector_hooks(cfg, "copilot", r)
    return [row for row in r.checks if row["label"] == "Copilot hooks"]


@pytest.mark.parametrize("case", _COPILOT, ids=_case_id)
def test_the_files_setup_writes_are_guarded(tmp_path, monkeypatch, case):
    cfg, _paths = _copilot(tmp_path, monkeypatch, case)
    _write(tmp_path, "{home}/.copilot/settings.json", json.dumps({"disableAllHooks": False}))
    assert hook_integrity.agent_hook_switch_problems(cfg, "copilot") == []
    assert hook_integrity.unrunnable_hook_problem(cfg, "copilot") == ""
    assert cmd_status._hook_runtime_degraded_suffix(cfg, "copilot") == ""
    assert _readiness(cfg, "copilot") is None


@pytest.mark.parametrize("case, layer, platform", _SWITCH_CASES)
def test_disable_all_hooks_is_reported_by_every_check(tmp_path, monkeypatch, case, layer, platform):
    cfg, _paths = _copilot(tmp_path, monkeypatch, case, platform)
    settings = _write(tmp_path, layer, json.dumps({"disableAllHooks": True}))

    problems = hook_integrity.agent_hook_switch_problems(cfg, "copilot")
    assert len(problems) == 1 and str(settings) in problems[0], problems
    assert "not guarding its tool calls" in problems[0]
    assert f"remove disableAllHooks from {settings}" in hook_integrity.repair_command("copilot", problems[0])
    # status, guardrail status and the setup read-back.
    assert hook_integrity.unrunnable_hook_problem(cfg, "copilot") == problems[0]
    assert problems[0] in cmd_status._hook_runtime_degraded_suffix(cfg, "copilot")
    step = _readiness(cfg, "copilot")
    assert step is not None and step.status == "fail" and problems[0] in step.detail, step
    if platform == "posix":
        rows = _doctor_rows(cfg, monkeypatch)
        assert rows and all(row["status"] == "fail" for row in rows), rows


@pytest.mark.parametrize("case", _COPILOT, ids=_case_id)
def test_a_later_settings_layer_turns_the_hooks_back_on(tmp_path, monkeypatch, case):
    cfg, _paths = _copilot(tmp_path, monkeypatch, case)
    layers = _layers(case)
    _write(tmp_path, layers[0], json.dumps({"disableAllHooks": True}))
    _write(tmp_path, layers[-1], json.dumps({"disableAllHooks": False}))
    assert hook_integrity.agent_hook_switch_problems(cfg, "copilot") == []


@pytest.mark.parametrize("content", ['{"disableAllHooks": "yes"}', "{not json", "[]"])
def test_unreadable_copilot_settings_fail_closed(tmp_path, monkeypatch, content):
    case = next(c for c in _COPILOT if c["scope"] == "user")
    cfg, _paths = _copilot(tmp_path, monkeypatch, case)
    settings = _write(tmp_path, "{home}/.copilot/settings.json", content)
    problems = hook_integrity.agent_hook_switch_problems(cfg, "copilot")
    assert len(problems) == 1 and str(settings) in problems[0], problems
    assert "cannot tell whether Copilot runs its hooks" in problems[0]
    assert hook_integrity.unrunnable_hook_problem(cfg, "copilot") == problems[0]
    step = _readiness(cfg, "copilot")
    assert step is not None and step.status == "fail", step


@pytest.mark.parametrize(
    "connector, path, content",
    [
        ("claudecode", "{home}/.claude/settings.json", None),
        ("codex", "{home}/.codex/config.toml", "\n[features]\nhooks = false\n"),
    ],
)
def test_every_agent_hook_switch_fails_the_setup_read_back(tmp_path, monkeypatch, connector, path, content):
    case = next(c for c in _CASES if c["connector"] == connector and c["os"] == "posix" and c["scope"] == "user")
    cfg, paths = _install(tmp_path, monkeypatch, case)
    target = Path(path.replace("{home}", str(tmp_path / "home")))
    assert str(target) in paths
    if content is None:
        document = json.loads(target.read_text(encoding="utf-8"))
        document["disableAllHooks"] = True
        target.write_text(json.dumps(document), encoding="utf-8")
    else:
        target.write_text(target.read_text(encoding="utf-8") + content, encoding="utf-8")
    assert hook_integrity.agent_hook_switch_problems(cfg, connector)
    step = _readiness(cfg, connector)
    assert step is not None and step.status == "fail", step
