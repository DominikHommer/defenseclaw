# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from unittest.mock import patch

import defenseclaw.commands.cmd_acp as cmd_acp_module
import pytest
from click.testing import CliRunner
from defenseclaw.acp_catalog import ACP_AGENT_ENTRY_POINTS, ACP_CLIENT_ENTRY_CAPABILITIES
from defenseclaw.commands.cmd_acp import _write_token, acp_cmd
from defenseclaw.config import ACPBinding, ACPProfile

from tests.helpers import cleanup_app, make_app_context


def _binary(path: Path) -> str:
    path.write_bytes(path.name.encode("utf-8"))
    path.chmod(0o700)
    return str(path.resolve())


def _app(tmp_path: Path):
    data = tmp_path / "data"
    data.mkdir()
    return make_app_context(str(data))


def _isolate_client_config(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "AppData" / "Roaming"))


def _zed_settings(tmp_path: Path) -> Path:
    if os.name == "nt":
        return tmp_path / "AppData" / "Roaming" / "Zed" / "settings.json"
    return tmp_path / ".config" / "zed" / "settings.json"


def test_catalog_exposes_native_only_connector_coverage():
    result = CliRunner().invoke(acp_cmd, ["catalog"])
    assert result.exit_code == 0, result.output
    catalog = json.loads(result.output)
    assert catalog["protocol"]["release"] == "schema-v1.21.0"
    assert catalog["environment_variables"] == []
    canonical = json.loads((Path(__file__).parents[2] / "internal" / "inventory" / "acp_registry.json").read_text(encoding="utf-8"))
    assert catalog == canonical
    assert set(ACP_AGENT_ENTRY_POINTS) == {agent["id"] for agent in catalog["agents"]}
    for client in catalog["clients"]:
        capabilities = ACP_CLIENT_ENTRY_CAPABILITIES[client["id"]]
        assert capabilities.entries_key == client["entry_capabilities"]["entries_key"]
        assert capabilities.managed_type == client["entry_capabilities"]["managed_type"]
        assert capabilities.launch_keys == set(client["entry_capabilities"]["launch_keys"])
        assert capabilities.preference_keys == set(client["entry_capabilities"]["preference_keys"])
    assert any(agent["id"] == "devin" and agent["kind"] == "native" for agent in catalog["agents"])

    # The guard admits native vendor ACP modes only. A bridge, companion
    # server or gateway-backed shim would put a process DefenseClaw does not
    # control inside the security boundary, so none may reappear in the
    # catalog, and the connectors that used to reach ACP that way must report
    # no ACP claim rather than pointing at an agent that is gone.
    assert {agent["kind"] for agent in catalog["agents"]} == {"native"}
    assert {agent["id"] for agent in catalog["agents"]} == {
        "kiro",
        "cursor",
        "opencode",
        "hermes",
        "copilot",
        "devin",
    }
    agent_ids = {agent["id"] for agent in catalog["agents"]}
    for row in catalog["connector_coverage"]:
        if row["acp_support"] == "none":
            assert "agent_id" not in row, row
        else:
            assert row["agent_id"] in agent_ids, row
    retired = {"codex", "claudecode", "amp", "antigravity", "openclaw", }
    reporting_none = {row["connector_id"] for row in catalog["connector_coverage"] if row["acp_support"] == "none"}
    assert retired <= reporting_none


def test_token_secures_parent_directory_before_file_creation(tmp_path):
    with patch("defenseclaw.commands.cmd_acp.make_private_directory") as protect:
        token = _write_token(str(tmp_path))
    protect.assert_called_once_with(tmp_path / "acp")
    assert token.is_file()


def test_zed_setup_defaults_observe_and_preserves_foreign_entries(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    settings.write_text('// operator comment\n{"theme": "Ayu", "agent_servers": {"Foreign": {"command": "other"}},}\n')
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    try:
        with patch("defenseclaw.commands.cmd_acp._agent_version", return_value="kiro-cli 2.21.3"):
            result = CliRunner().invoke(
                acp_cmd,
                [
                    "setup",
                    "--client",
                    "zed",
                    "--agent",
                    "kiro",
                    "--guard-binary",
                    guard,
                    "--agent-binary",
                    agent,
                    "--json-output",
                ],
                obj=app,
            )
        assert result.exit_code == 0, result.output
        rewritten = settings.read_text()
        assert rewritten.startswith("// operator comment\n")
        configured = json.loads(rewritten.split("\n", 1)[1])
        assert configured["theme"] == "Ayu"
        assert configured["agent_servers"]["Foreign"]["command"] == "other"
        managed = configured["agent_servers"]["DefenseClaw · Kiro"]
        assert managed["command"] == guard
        assert managed["args"][managed["args"].index("--mode") + 1] == "observe"
        lock = json.loads((Path(data_dir) / "acp" / "zed-kiro.contract-lock.json").read_text())
        assert lock["protocol"]["schema_version"] == "schema-v1.21.0"
        assert lock["agent"]["version"] == "kiro-cli 2.21.3"
        assert lock["guard"]["managed_custody"] is False
        assert app.cfg.acp.mode == "observe"
        saved = (Path(data_dir) / "config.yaml").read_text(encoding="utf-8")
        assert "default_profile: default" in saved
        if os.name != "nt":
            assert (Path(data_dir) / "acp" / ".token").stat().st_mode & 0o077 == 0
    finally:
        cleanup_app(app, db_path, data_dir)


def test_setup_activate_and_remove_are_surgical(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    try:
        with patch("defenseclaw.commands.cmd_acp._agent_version", return_value="v"):
            result = CliRunner().invoke(
                acp_cmd,
                [
                    "setup",
                    "--client",
                    "jetbrains",
                    "--agent",
                    "kiro",
                    "--activate",
                    "--guard-binary",
                    guard,
                    "--agent-binary",
                    agent,
                ],
                obj=app,
            )
        assert result.exit_code == 0, result.output
        path = tmp_path / ".jetbrains" / "acp.json"
        document = json.loads(path.read_text())
        document["agent_servers"]["Foreign"] = {"command": "other"}
        path.write_text(json.dumps(document))
        result = CliRunner().invoke(acp_cmd, ["remove", "--client", "jetbrains", "--agent", "kiro"], obj=app)
        assert result.exit_code == 0, result.output
        remaining = json.loads(path.read_text())["agent_servers"]
        assert "Foreign" in remaining
        assert "DefenseClaw · Kiro" not in remaining
    finally:
        cleanup_app(app, db_path, data_dir)


@pytest.mark.parametrize("entry_names", [[], ["My Kiro", "Kiro (2)"]], ids=["reserved", "adopted-and-numbered"])
def test_editor_preferences_do_not_drift_guarded_entry_pins(tmp_path, monkeypatch, entry_names):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    settings = _zed_settings(tmp_path)
    try:
        if entry_names:
            settings.parent.mkdir(parents=True)
            settings.write_text(json.dumps({"agent_servers": {
                name: {"command": agent, "args": ["acp"]} for name in entry_names
            }}))
            args = ["adopt", "--client", "zed", "--guard-binary", guard, "--yes", "--json-output"]
        else:
            args = ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent]
        result = CliRunner().invoke(acp_cmd, args, obj=app)
        assert result.exit_code == 0, result.output
        document = json.loads(settings.read_text())
        document.update(default_mode="ask", theme="Ayu")
        names = entry_names or ["DefenseClaw · Kiro"]
        for name in names:
            document["agent_servers"][name]["default_mode"] = "ask"
        settings.write_text(json.dumps(document))
        verified = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert verified.exit_code == 0, verified.output
        # The Go guard parses the entire settings file as JSON before
        # hashing entries; Python must not accept non-JSON numbers elsewhere.
        malformed = dict(document, unrelated=float("nan"))
        settings.write_text(json.dumps(malformed))
        refused = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert refused.exit_code != 0, refused.output
        for name in names:
            changed = json.loads(json.dumps(document))
            changed["agent_servers"][name]["env"]["CHANGED_LAUNCH"] = "yes"
            settings.write_text(json.dumps(changed))
            refused = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
            assert refused.exit_code != 0, (name, refused.output)
        # Setting up a different pair in the same editor must not silently
        # bless the changed environment in this pair's entry.
        lock_path = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
        original_lock = lock_path.read_bytes()
        other_agent = _binary(tmp_path / "devin")
        other = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "devin", "--profile", "other",
             "--guard-binary", guard, "--agent-binary", other_agent],
            obj=app,
        )
        assert other.exit_code == 0, other.output
        assert lock_path.read_bytes() == original_lock
        refused = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert refused.exit_code != 0, refused.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_setup_rolls_back_client_token_and_lock_when_config_save_fails(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    original = b'{"theme":"original"}\n'
    settings.write_bytes(original)
    try:
        with (
            patch("defenseclaw.commands.cmd_acp._agent_version", return_value="v"),
            patch.object(app.cfg, "save", side_effect=OSError("forced save failure")),
        ):
            result = CliRunner().invoke(
                acp_cmd,
                ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
                obj=app,
            )
        assert result.exit_code != 0
        assert settings.read_bytes() == original
        assert not (Path(data_dir) / "acp" / ".token").exists()
        assert not (Path(data_dir) / "acp" / "zed-kiro.contract-lock.json").exists()
        assert not app.cfg.acp.enabled
    finally:
        cleanup_app(app, db_path, data_dir)


def test_verify_detects_agent_digest_drift(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent_path = tmp_path / "kiro-cli"
    agent = _binary(agent_path)
    try:
        result = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert result.exit_code == 0, result.output
        assert CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app).exit_code == 0

        agent_path.write_bytes(b"drifted-binary")
        result = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code != 0
        assert "agent executable digest has drifted" in result.output

        agent_path.write_bytes(b"test-binary")
        lock_path = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
        lock = json.loads(lock_path.read_text())
        for invalid_agent in (None, [], "unproven", 42):
            lock_path.write_text(json.dumps(dict(lock, agent=invalid_agent)))
            before = lock_path.read_bytes()
            result = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
            assert result.exit_code != 0
            assert "contract lock identity does not match" in result.output
            assert "run defenseclaw" in result.output
            assert "--profile" in result.output
            assert lock_path.read_bytes() == before
    finally:
        cleanup_app(app, db_path, data_dir)


def test_doctor_reports_acp_bindings_and_fails_on_drift(tmp_path, monkeypatch):
    """GAP-1534: doctor lists each binding and FAILs with the fix on drift."""
    from defenseclaw.commands.cmd_doctor import _check_acp_bindings, _DoctorResult

    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent_path = tmp_path / "kiro-cli"
    agent = _binary(agent_path)
    try:
        empty = _DoctorResult()
        _check_acp_bindings(app.cfg, empty)
        assert empty.checks == []  # ACP is optional: no binding, no row

        result = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert result.exit_code == 0, result.output
        healthy = _DoctorResult()
        _check_acp_bindings(app.cfg, healthy)
        [row] = healthy.checks
        assert row["label"] == "ACP binding [zed/kiro]"
        assert row["status"] == "pass" and "healthy; profile default (observe)" in row["detail"]

        agent_path.write_bytes(b"drifted-binary")
        drifted = _DoctorResult()
        _check_acp_bindings(app.cfg, drifted)
        [row] = drifted.checks
        assert row["status"] == "fail"
        assert "agent executable digest has drifted" in row["detail"]
        assert row["remediation"].startswith("defenseclaw acp setup --client zed --agent kiro --profile default")
        assert "--activate" not in row["remediation"]
    finally:
        cleanup_app(app, db_path, data_dir)


def test_verify_detects_client_configuration_drift(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    try:
        result = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert result.exit_code == 0, result.output
        settings = _zed_settings(tmp_path)
        document = json.loads(settings.read_text())
        document["agent_servers"]["DefenseClaw · Kiro"]["env"]["CHANGED_LAUNCH"] = "yes"
        settings.write_text(json.dumps(document))

        result = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code != 0
        assert "client configuration digest has drifted" in result.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_same_agent_in_two_clients_uses_distinct_contract_locks(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    try:
        runner = CliRunner()
        for client in ("zed", "jetbrains"):
            result = runner.invoke(
                acp_cmd,
                [
                    "setup",
                    "--client",
                    client,
                    "--agent",
                    "kiro",
                    "--guard-binary",
                    guard,
                    "--agent-binary",
                    agent,
                ],
                obj=app,
            )
            assert result.exit_code == 0, result.output
        zed_lock = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
        jetbrains_lock = Path(data_dir) / "acp" / "jetbrains-kiro.contract-lock.json"
        assert zed_lock.is_file() and jetbrains_lock.is_file()
        assert zed_lock.read_bytes() != jetbrains_lock.read_bytes()

        result = runner.invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code == 0, result.output
        assert not zed_lock.exists()
        assert jetbrains_lock.exists()
        assert "kiro" in app.cfg.acp.agents
        assert "jetbrains" in app.cfg.acp.clients
    finally:
        cleanup_app(app, db_path, data_dir)


def test_multiple_agents_in_one_client_keep_every_contract_current(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    kiro = _binary(tmp_path / "kiro-cli")
    cursor = _binary(tmp_path / "cursor-agent")
    try:
        runner = CliRunner()
        for agent, executable in (("kiro", kiro), ("cursor", cursor)):
            result = runner.invoke(
                acp_cmd,
                [
                    "setup",
                    "--client",
                    "zed",
                    "--agent",
                    agent,
                    "--guard-binary",
                    guard,
                    "--agent-binary",
                    executable,
                ],
                obj=app,
            )
            assert result.exit_code == 0, result.output

        for agent in ("kiro", "cursor"):
            result = runner.invoke(acp_cmd, ["verify", "--client", "zed", "--agent", agent], obj=app)
            assert result.exit_code == 0, result.output

        result = runner.invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "cursor"], obj=app)
        assert result.exit_code == 0, result.output
        result = runner.invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code == 0, result.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_managed_setup_uses_provisioned_binding_token_without_mutating_central_policy(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    runtime_data = tmp_path / "user-runtime"
    token = runtime_data / "acp" / "zed-kiro.token"
    token.parent.mkdir(parents=True, mode=0o700)
    token.write_text("0" * 64 + "\n")
    token.chmod(0o600)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    app.cfg.deployment_mode = "managed_enterprise"
    app.cfg.acp.enabled = True
    app.cfg.acp.mode = "action"
    app.cfg.acp.default_profile = "locked"
    app.cfg.acp.clients = {"zed": ACPBinding(enabled=True, profile="locked")}
    app.cfg.acp.agents = {"kiro": ACPBinding(enabled=True, profile="locked")}
    app.cfg.acp.profiles = {"locked": ACPProfile(fail_mode="closed", allowed_clients=["zed"], allowed_agents=["kiro"])}
    before = json.dumps(app.cfg.acp, default=lambda value: value.__dict__, sort_keys=True)
    try:
        with patch.object(app.cfg, "save", side_effect=AssertionError("managed enrollment must not save policy")):
            result = CliRunner().invoke(
                acp_cmd,
                [
                    "setup",
                    "--client",
                    "zed",
                    "--agent",
                    "kiro",
                    "--profile",
                    "locked",
                    "--activate",
                    "--managed",
                    "--runtime-data-dir",
                    str(runtime_data),
                    "--token-file",
                    str(token),
                    "--guard-binary",
                    guard,
                    "--agent-binary",
                    agent,
                    "--json-output",
                ],
                obj=app,
            )
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["managed"] is True
        assert json.dumps(app.cfg.acp, default=lambda value: value.__dict__, sort_keys=True) == before
        settings = json.loads(_zed_settings(tmp_path).read_text())
        args = settings["agent_servers"]["DefenseClaw · Kiro"]["args"]
        assert args[args.index("--token-file") + 1] == str(token.resolve())
        lock = runtime_data / "acp" / "zed-kiro.contract-lock.json"
        assert lock.is_file()
        assert json.loads(lock.read_text(encoding="utf-8"))["guard"]["managed_custody"] is True
    finally:
        cleanup_app(app, db_path, data_dir)


def test_managed_setup_rejects_pair_outside_central_policy(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    app.cfg.deployment_mode = "managed_enterprise"
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    try:
        result = CliRunner().invoke(
            acp_cmd,
            [
                "setup",
                "--client",
                "zed",
                "--agent",
                "kiro",
                "--managed",
                "--guard-binary",
                guard,
                "--agent-binary",
                agent,
            ],
            obj=app,
        )
        assert result.exit_code != 0
        assert "central enterprise ACP policy does not authorize" in result.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_remove_rolls_back_editor_lock_and_policy_on_save_failure(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    try:
        runner = CliRunner()
        result = runner.invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert result.exit_code == 0, result.output
        settings = _zed_settings(tmp_path)
        lock = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
        settings_before = settings.read_bytes()
        lock_before = lock.read_bytes()

        with patch.object(app.cfg, "save", side_effect=OSError("forced save failure")):
            result = runner.invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code != 0
        assert settings.read_bytes() == settings_before
        assert lock.read_bytes() == lock_before
        assert app.cfg.acp.enabled
        assert "kiro" in app.cfg.acp.agents
    finally:
        cleanup_app(app, db_path, data_dir)


def test_remove_reports_one_rollback_failure_and_continues_restoring(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    try:
        runner = CliRunner()
        result = runner.invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert result.exit_code == 0, result.output
        lock = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
        lock_before = lock.read_bytes()
        original_restore = cmd_acp_module._restore
        restore_calls = 0

        def partially_failing_restore(path, snapshot):
            nonlocal restore_calls
            restore_calls += 1
            if restore_calls == 1:
                raise OSError("forced restore failure")
            original_restore(path, snapshot)

        with (
            patch.object(app.cfg, "save", side_effect=OSError("forced save failure")),
            patch("defenseclaw.commands.cmd_acp._restore", side_effect=partially_failing_restore),
        ):
            result = runner.invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code != 0
        assert restore_calls >= 2
        assert "rollback problems:" in result.output
        assert lock.read_bytes() == lock_before
    finally:
        cleanup_app(app, db_path, data_dir)


def test_detect_classifies_guarded_direct_and_client_registry_entries(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    settings.write_text(
        json.dumps(
            {
                "agent_servers": {
                    # Already guarded.
                    "DefenseClaw · Kiro": {"command": "/opt/bin/defenseclaw-acp", "args": []},
                    # A direct launch of a native agent: wrappable.
                    "My Cursor": {"command": "/usr/local/bin/agent", "args": ["acp", "--verbose"]},
                    # Resolved by the client's own registry: unguarded, but no
                    # argv exists for the guard to wrap.
                    "cursor": {"type": "registry"},
                    # Not an ACP agent DefenseClaw knows.
                    "Something Else": {"command": "unrelated-binary", "args": []},
                }
            }
        )
    )
    result = CliRunner().invoke(acp_cmd, ["detect", "--json-output"])
    assert result.exit_code == 0, result.output
    zed = next(item for item in json.loads(result.output)["clients"] if item["client"] == "zed")

    assert [item["entry"] for item in zed["guarded"]] == ["DefenseClaw · Kiro"]
    assert [(item["entry"], item["agent"]) for item in zed["adoptable"]] == [("My Cursor", "cursor")]
    assert [item["entry"] for item in zed["client_registry"]] == ["cursor"]
    assert [item["entry"] for item in zed["foreign"]] == ["Something Else"]
    # kiro is already guarded and cursor is accounted for, so neither is
    # offered as "installed but not configured here".
    assert "kiro" not in zed["installable"]
    assert "cursor" not in zed["installable"]


def test_adopt_points_the_operators_own_entry_at_the_guard(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    settings.write_text(
        json.dumps(
            {
                "agent_servers": {
                    "Kiro": {"command": agent, "args": ["acp"], "env": {"KEEP": "me"}},
                }
            }
        )
    )
    try:
        with patch("defenseclaw.commands.cmd_acp._agent_version", return_value="kiro-cli 2.22.0"):
            result = CliRunner().invoke(
                acp_cmd,
                ["adopt", "--client", "zed", "--guard-binary", guard, "--yes", "--json-output"],
                obj=app,
            )
        assert result.exit_code == 0, result.output
        adopted = json.loads(result.output)["adopted"]
        assert adopted == [{"agent": "kiro", "client": "zed", "entry": "Kiro"}]

        servers = json.loads(settings.read_text())["agent_servers"]
        # The operator's own entry now launches the guard, keeps its key and
        # its env, and carries the same argv the managed entry got.
        assert servers["Kiro"]["command"] == guard
        assert servers["Kiro"]["env"] == {"KEEP": "me"}
        assert "DefenseClaw · Kiro" not in servers
        # The wrapped agent is the one that was already configured (compare
        # basenames: macOS resolves the temp path through /private).
        assert any(str(value).endswith("kiro-cli") for value in servers["Kiro"]["args"])
        # No unguarded path to the agent is left behind.
        assert app.cfg.acp.mode == "observe"

        changed = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard,
             "--agent-binary", agent, "--profile", "locked", "--activate", "--json-output"],
            obj=app,
        )
        assert changed.exit_code == 0, changed.output
        servers = json.loads(settings.read_text())["agent_servers"]
        assert set(servers) == {"Kiro"}
        assert "locked" in servers["Kiro"]["args"]
        assert "action" in servers["Kiro"]["args"]
        verified = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert verified.exit_code == 0, verified.output
        equivalent_data_dir = str(Path(data_dir) / ".." / Path(data_dir).name)
        assert not cmd_acp_module._verify_binding(equivalent_data_dir, "zed", "kiro", app.cfg.acp)
        # A copied guarded entry with stale metadata must also be checked.
        # Under the reserved name it is DefenseClaw's and verify reports its
        # launch. Under another name it is unproven and verify reports that
        # unknown launch while removal still leaves it with a warning.
        stale = dict(servers["Kiro"], args=list(servers["Kiro"]["args"]))
        stale["args"][stale["args"].index("--profile") + 1] = "default"
        for name in ("DefenseClaw · Kiro", "Stale"):
            settings.write_text(json.dumps({"agent_servers": {**servers, name: stale}}))
            verified = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
            problems = cmd_acp_module._verify_binding(str(data_dir), "zed", "kiro", app.cfg.acp)
            if name == "Stale":
                assert verified.exit_code != 0 and "Stale" in verified.output, verified.output
                assert cmd_acp_module._unproven_pair_entries("zed", "kiro", str(data_dir)) == ["Stale"]
            else:
                assert verified.exit_code != 0, verified.output
                assert f"editor launch command does not match the lock: {name}" in problems, problems
        settings.write_text(json.dumps({"agent_servers": servers}))

        # Re-running finds nothing to adopt rather than double-wrapping.
        again = CliRunner().invoke(acp_cmd, ["adopt", "--client", "zed", "--yes", "--json-output"], obj=app)
        assert again.exit_code == 0, again.output
        assert json.loads(again.output)["adopted"] == []
        removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert removed.exit_code == 0, removed.output
        assert not settings.exists()
        collision = {"agent_servers": {"DefenseClaw · Kiro": {"command": "other", "args": []}}}
        settings.write_text(json.dumps(collision))
        before = settings.read_bytes()
        for command in (
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
            ["remove", "--client", "zed", "--agent", "kiro"],
        ):
            refused = CliRunner().invoke(acp_cmd, command, obj=app)
            assert refused.exit_code != 0, refused.output
            assert "rename that entry" in refused.output
            assert settings.read_bytes() == before
    finally:
        cleanup_app(app, db_path, data_dir)


def test_second_pair_in_another_mode_does_not_repoint_global_fallbacks(tmp_path, monkeypatch):
    """Per-pair setup must not promote or demote pairs it was not asked about.

    `acp.mode` and `acp.default_profile` are global fallbacks. Writing them on
    every setup meant configuring a second pair in observe mode flipped the
    default out from under any pair that inherits it, and left `acp.mode`
    describing whichever pair happened to be configured last.
    """

    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "guard")
    kiro = _binary(tmp_path / "kiro-cli")
    agent_binary = _binary(tmp_path / "agent")
    try:
        with patch("defenseclaw.commands.cmd_acp._agent_version", return_value="probe"):
            first = CliRunner().invoke(
                acp_cmd,
                ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard,
                 "--agent-binary", kiro, "--profile", "locked", "--activate", "--json-output"],
                obj=app,
            )
            assert first.exit_code == 0, first.output
            assert app.cfg.acp.mode == "action"
            assert app.cfg.acp.default_profile == "locked"

            second = CliRunner().invoke(
                acp_cmd,
                ["setup", "--client", "zed", "--agent", "cursor", "--guard-binary", guard,
                 "--agent-binary", agent_binary, "--profile", "watch", "--json-output"],
                obj=app,
            )
            assert second.exit_code == 0, second.output

        # The observe pair did not drag the global fallbacks with it.
        assert app.cfg.acp.mode == "action"
        assert app.cfg.acp.default_profile == "locked"
        # Each pair carries its own profile, and each profile its own mode.
        assert app.cfg.acp.bindings["zed/kiro"].profile == "locked"
        assert app.cfg.acp.bindings["zed/cursor"].profile == "watch"
        assert app.cfg.acp.profiles["locked"].mode == "action"
        assert app.cfg.acp.profiles["watch"].mode == "observe"
        assert app.cfg.acp.profile_for_pair("zed", "kiro") == "locked"
        assert app.cfg.acp.profile_for_pair("zed", "cursor") == "watch"
        # The shared pins stay profile-free so neither pair pulls the other.
        assert app.cfg.acp.clients["zed"].profile == ""
        assert app.cfg.acp.clients["zed"].enabled is True
    finally:
        cleanup_app(app, db_path, data_dir)


def test_activating_a_profile_another_pair_resolves_through_a_pin_is_refused(tmp_path, monkeypatch):
    """The mode-conflict check must see pairs that inherit, not only bindings.

    A pair configured before per-pair bindings existed resolves its profile
    through the client/agent pin. Looking only at `bindings` would let a later
    `--activate` flip that shared profile's mode and silently promote it.
    """

    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "guard")
    kiro = _binary(tmp_path / "kiro-cli")
    agent_binary = _binary(tmp_path / "agent")
    try:
        with patch("defenseclaw.commands.cmd_acp._agent_version", return_value="probe"):
            first = CliRunner().invoke(
                acp_cmd,
                ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard,
                 "--agent-binary", kiro, "--profile", "shared", "--json-output"],
                obj=app,
            )
            assert first.exit_code == 0, first.output
            # Simulate a pre-per-pair config: the pair resolves through pins.
            app.cfg.acp.bindings.pop("zed/kiro")
            app.cfg.acp.clients["zed"].profile = "shared"
            app.cfg.acp.agents["kiro"].profile = "shared"
            assert app.cfg.acp.profile_for_pair("zed", "kiro") == "shared"

            clash = CliRunner().invoke(
                acp_cmd,
                ["setup", "--client", "zed", "--agent", "cursor", "--guard-binary", guard,
                 "--agent-binary", agent_binary, "--profile", "shared", "--activate", "--json-output"],
                obj=app,
            )
        assert clash.exit_code != 0
        assert "zed/kiro" in clash.output
        assert "--profile" in clash.output
        # kiro was not promoted behind the operator's back.
        assert app.cfg.acp.profiles["shared"].mode == "observe"
    finally:
        cleanup_app(app, db_path, data_dir)


def test_verify_reports_profile_drift_after_a_hand_edit(tmp_path, monkeypatch):
    """Editing a pair's profile by hand must not read as healthy.

    The guard carries its profile in argv, pinned into the contract lock at
    setup, and the gateway refuses a request whose profile the configuration
    no longer assigns to that pair. Without this check `verify` and `status`
    kept reporting the binding healthy and the operator learned about it from
    a dead editor session instead.
    """

    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    settings.write_text("{}")
    guard = _binary(tmp_path / "guard")
    kiro = _binary(tmp_path / "kiro-cli")
    try:
        with patch("defenseclaw.commands.cmd_acp._agent_version", return_value="probe"):
            created = CliRunner().invoke(
                acp_cmd,
                ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard,
                 "--agent-binary", kiro, "--profile", "locked", "--json-output"],
                obj=app,
            )
        assert created.exit_code == 0, created.output
        healthy = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert healthy.exit_code == 0, healthy.output

        # Move the pair to a different profile without re-running setup.
        app.cfg.acp.profiles["watch"] = app.cfg.acp.profiles["locked"]
        app.cfg.acp.bindings["zed/kiro"] = ACPBinding(enabled=True, profile="watch")
        drifted = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert drifted.exit_code != 0
        assert "no longer matches the configured" in drifted.output
        assert "re-run acp setup" in drifted.output

        # status surfaces it too, so the operator does not need to guess which
        # binding to verify.
        listed = CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app)
        assert listed.exit_code == 0, listed.output
        binding = json.loads(listed.output)["bindings"]["zed/kiro"]
        assert binding["healthy"] is False
        assert binding["profile"] == "watch"
        assert binding["profile_source"] == "binding"

        # GAP-1501: without --json the posture is a readable summary.
        human = CliRunner().invoke(acp_cmd, ["status"], obj=app)
        assert human.exit_code == 0, human.output
        # GAP-1732: the header holds only guard-wide facts; mode and
        # profile live on each binding row.
        assert human.output.startswith("ACP guard: on (1 binding)\n")
        assert "default profile" not in human.output
        assert "zed/kiro" in human.output and "NEEDS ATTENTION" in human.output
        assert "acp status --json" in human.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_remove_without_entry_is_a_noop_and_last_remove_restores_no_file(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    settings = _zed_settings(tmp_path)
    try:
        runner = CliRunner()
        result = runner.invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code == 0, result.output
        assert "Nothing to remove" in result.output
        assert not settings.exists()

        result = runner.invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert result.exit_code == 0, result.output
        result = runner.invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code == 0, result.output
        assert "Removed the DefenseClaw kiro entry" in result.output
        assert not settings.exists()
    finally:
        cleanup_app(app, db_path, data_dir)


def test_verify_without_options_checks_every_binding(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    kiro = _binary(tmp_path / "kiro-cli")
    try:
        runner = CliRunner()
        result = runner.invoke(acp_cmd, ["verify"], obj=app)
        assert result.exit_code != 0
        assert "No DefenseClaw ACP bindings are configured" in result.output
        for client in ("zed", "jetbrains"):
            result = runner.invoke(
                acp_cmd,
                ["setup", "--client", client, "--agent", "kiro", "--guard-binary", guard, "--agent-binary", kiro],
                obj=app,
            )
            assert result.exit_code == 0, result.output
        result = runner.invoke(acp_cmd, ["verify"], obj=app)
        assert result.exit_code == 0, result.output
        assert "Verified jetbrains/kiro" in result.output and "Verified zed/kiro" in result.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_refresh_repins_only_the_upgraded_defenseclaw_guard(tmp_path, monkeypatch):
    # GAP-1294: an upgrade replaces defenseclaw-acp, and every editor entry
    # then failed closed on the stale guard digest until acp setup was rerun.
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard_path = tmp_path / "bin" / "defenseclaw-acp"
    guard_path.parent.mkdir()
    guard = _binary(guard_path)
    agent_path = tmp_path / "kiro-cli"
    agent = _binary(agent_path)
    try:
        setup = ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent]
        assert CliRunner().invoke(acp_cmd, setup, obj=app).exit_code == 0
        verify = ["verify", "--client", "zed", "--agent", "kiro"]

        old_sha = hashlib.sha256(guard_path.read_bytes()).hexdigest()
        guard_path.write_bytes(b"upgraded-guard")
        result = CliRunner().invoke(acp_cmd, verify, obj=app)
        assert result.exit_code != 0 and "defenseclaw acp refresh" in result.output

        # The installer names the guard it replaced; a lock pinned to another
        # guard is left alone.
        result = CliRunner().invoke(acp_cmd, ["refresh", "--from-sha256", "0" * 64], obj=app)
        assert result.exit_code == 0 and result.output == ""
        result = CliRunner().invoke(acp_cmd, ["refresh", "--from-sha256", old_sha], obj=app)
        assert result.exit_code == 0 and "Re-pinned the DefenseClaw ACP guard for zed/kiro" in result.output
        assert CliRunner().invoke(acp_cmd, verify, obj=app).exit_code == 0
        assert CliRunner().invoke(acp_cmd, ["refresh"], obj=app).output == ""  # nothing left to do

        # A changed agent binary is not re-pinned.
        agent_path.write_bytes(b"other-agent")
        CliRunner().invoke(acp_cmd, ["refresh"], obj=app)
        result = CliRunner().invoke(acp_cmd, verify, obj=app)
        assert result.exit_code != 0 and "agent executable digest has drifted" in result.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_source_install_and_doctor_fix_repin_only_defenseclaws_guard(tmp_path, monkeypatch):
    # make all re-pins the entries that start the guard it just published;
    # doctor --fix plans the same refresh, applies it once, and never
    # re-pins a changed agent binary.
    from defenseclaw.commands.cmd_doctor import _fix_acp_guard_pins

    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard_path = tmp_path / "bin" / "defenseclaw-acp"
    guard_path.parent.mkdir()
    guard = _binary(guard_path)
    agent_path = tmp_path / "kiro-cli"
    agent = _binary(agent_path)
    try:
        setup = ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent]
        assert CliRunner().invoke(acp_cmd, setup, obj=app).exit_code == 0
        guard_path.write_bytes(b"source-build-guard")
        other = tmp_path / "other" / "defenseclaw-acp"
        other.parent.mkdir()
        _binary(other)
        assert CliRunner().invoke(acp_cmd, ["refresh", "--guard-path", str(other)], obj=app).output == ""
        result = CliRunner().invoke(acp_cmd, ["refresh", "--guard-path", guard], obj=app)
        assert "Re-pinned the DefenseClaw ACP guard for zed/kiro" in result.output

        guard_path.write_bytes(b"upgraded-guard")
        agent_path.write_bytes(b"updated-agent")
        tag, plan = _fix_acp_guard_pins(app.cfg, assume_yes=True, plan_only=True)
        assert tag == "plan" and "zed/kiro" in plan and "defenseclaw acp setup --client zed --agent kiro" in plan
        assert _fix_acp_guard_pins(app.cfg, assume_yes=True)[0] == "pass"
        tag, detail = _fix_acp_guard_pins(app.cfg, assume_yes=True, plan_only=True)
        assert tag == "skip" and "pins are current" in detail
        result = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert "agent executable digest has drifted" in result.output
        assert "guard executable digest has drifted" not in result.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_setup_and_remove_print_each_slow_step_and_keep_json_clean(tmp_path, monkeypatch):
    """GAP-1835: setup and remove ran for minutes on Windows with no output at all."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    setup = ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent]
    try:
        result = CliRunner().invoke(acp_cmd, setup, obj=app)
        assert result.exit_code == 0, result.output
        for step in ("checking the guard and agent executables", "Pinning the guard and agent executable digests",
                     "Saving the ACP policy", "Recording the change with the gateway"):
            assert step in result.stderr
        assert result.stdout.startswith("Configured kiro through DefenseClaw in zed")

        result = CliRunner().invoke(acp_cmd, [*setup, "--json-output"], obj=app)
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["agent"] == "kiro" and "Pinning" not in result.stderr

        result = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code == 0, result.output
        assert "Removing the DefenseClaw kiro entry" in result.stderr
        assert "Recording the change with the gateway" in result.stderr
    finally:
        cleanup_app(app, db_path, data_dir)


def test_setup_returns_once_the_gateway_has_loaded_the_guard(tmp_path, monkeypatch):
    """GAP-2135: an editor started right after setup was refused with HTTP 503."""
    from defenseclaw.gateway import OrchestratorClient

    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    answers = [
        {"enabled": False, "profiles": {}},
        {"enabled": True, "profiles": {"r4x": {"mode": "observe"}}},
        {"enabled": True, "profiles": {"r4x": {"mode": "action"}}},
    ]
    calls: list[int] = []

    def acp_profiles(_self):
        calls.append(1)
        return answers[min(len(calls), len(answers)) - 1]

    monkeypatch.setattr(OrchestratorClient, "acp_profiles", acp_profiles)
    monkeypatch.setattr(cmd_acp_module.time, "sleep", lambda _seconds: None)
    setup = ["setup", "--client", "zed", "--agent", "kiro", "--activate", "--profile", "r4x",
             "--guard-binary", guard, "--agent-binary", agent]
    try:
        result = CliRunner().invoke(acp_cmd, setup, obj=app)
        assert result.exit_code == 0, result.output
        assert len(calls) == 3
        assert "Waiting for the gateway to load the ACP policy" in result.stderr
        assert "has not loaded it yet" not in result.stderr

        # A gateway that never loads it: setup still succeeds, and says so.
        calls.clear()
        answers[:] = [{"enabled": False, "profiles": {}}]
        monkeypatch.setattr(cmd_acp_module, "_GATEWAY_ACP_APPLY_SECONDS", 0.0)
        result = CliRunner().invoke(acp_cmd, setup, obj=app)
        assert result.exit_code == 0, result.output
        assert "the gateway has not loaded it yet" in result.stderr
        assert result.stdout.startswith("Configured kiro through DefenseClaw in zed (action)")
    finally:
        cleanup_app(app, db_path, data_dir)


def _repair_args(output: str) -> list[str]:
    """The `acp setup` argv a failed verify told the operator to run."""
    import re
    import shlex

    command = output.split("; run ", 1)[1].strip().splitlines()[0]
    if os.name == "nt":
        words = [value.replace("''", "'") for value in re.findall(r"'((?:[^']|'')*)'", command)]
    else:
        words = shlex.split(command)[1:]
    assert words[:2] == ["acp", "setup"], command
    return words[1:]


def test_verify_repair_command_keeps_action_mode(tmp_path, monkeypatch):
    """Following verify's repair hint must not demote an action binding to observe/open."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    # With an unreadable lock the hint names no executables, so setup finds
    # the guard and the agent on PATH, as it does for the operator.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    suffix = ".exe" if os.name == "nt" else ""
    guard = _binary(bin_dir / f"defenseclaw-acp{suffix}")
    agent = _binary(bin_dir / f"kiro-cli{suffix}")
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))
    lock_path = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
    try:
        result = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--profile", "locked", "--activate",
             "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert result.exit_code == 0, result.output
        intact = lock_path.read_text()
        for broken in ("{", json.dumps({"version": 1}), None):
            if broken is None:
                # A readable lock: the hint also names the pinned executables.
                lock_path.write_text(intact)
                agent_path = Path(agent)
                agent_path.write_bytes(b"updated-binary")
            else:
                lock_path.write_text(broken)
            verified = CliRunner().invoke(acp_cmd, ["verify"], obj=app)
            assert verified.exit_code != 0, verified.output
            args = _repair_args(verified.output)
            assert "--activate" in args and args[args.index("--profile") + 1] == "locked"
            if broken is None:
                assert args[args.index("--agent-binary") + 1] == agent
                assert args[args.index("--guard-binary") + 1] == guard
            repaired = CliRunner().invoke(acp_cmd, args, obj=app)
            assert repaired.exit_code == 0, repaired.output
            locked = app.cfg.acp.profiles["locked"]
            assert (locked.mode, locked.fail_mode) == ("action", "closed")
            assert json.loads(lock_path.read_text())["mode"] == "action"
            assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code == 0

        # The mode a binding inherits counts too, and an unknown mode enforces.
        for profile_mode, fallback in (("", "action"), ("enforce", "observe")):
            app.cfg.acp.profiles["locked"].mode = profile_mode
            app.cfg.acp.mode = fallback
            assert "--activate" in cmd_acp_module.setup_repair_command(app.cfg, "zed", "kiro", str(data_dir))
        app.cfg.acp.profiles["locked"].mode = "observe"
        assert "--activate" not in cmd_acp_module.setup_repair_command(app.cfg, "zed", "kiro", str(data_dir))
    finally:
        cleanup_app(app, db_path, data_dir)


def test_doctor_repair_command_keeps_action_mode(tmp_path, monkeypatch):
    from defenseclaw.commands.cmd_doctor import _check_acp_bindings, _DoctorResult, _fix_acp_guard_pins

    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent_path = tmp_path / "kiro-cli"
    agent = _binary(agent_path)
    try:
        result = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--profile", "locked", "--activate",
             "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert result.exit_code == 0, result.output
        agent_path.write_bytes(b"drifted-binary")
        drifted = _DoctorResult()
        _check_acp_bindings(app.cfg, drifted)
        [row] = drifted.checks
        assert "--activate" in row["remediation"] and "locked" in row["remediation"]
        _tag, detail = _fix_acp_guard_pins(app.cfg, assume_yes=True, plan_only=True)
        assert "--activate" in detail
    finally:
        cleanup_app(app, db_path, data_dir)


def test_remove_and_setup_leave_unproven_guard_named_entries(tmp_path, monkeypatch):
    """A guard-like filename is not ownership: only a matching contract lock is."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    own = tmp_path / "operator" / "defenseclaw-acp"
    own.parent.mkdir()
    operator_guard = _binary(own)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    real_lock = str((Path(data_dir) / "acp" / "zed-kiro.contract-lock.json").resolve())
    other_lock = str(tmp_path / "elsewhere" / "zed-kiro.contract-lock.json")
    argv = ["--client", "zed", "--agent", "kiro"]
    variants = {
        "no lock": argv + ["--", "kiro-cli", "acp"],
        "missing lock": argv + ["--contract-lock", other_lock, "--", "kiro-cli", "acp"],
        # The pair's real lock exists but pins DefenseClaw's guard, not this file.
        "foreign command": argv + ["--contract-lock", real_lock, "--", "kiro-cli", "acp"],
    }
    try:
        for label, args in variants.items():
            alias = {"command": operator_guard, "args": args}
            settings.write_text(json.dumps({"agent_servers": {"My Kiro": alias}}))
            before = settings.read_bytes()
            removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
            assert removed.exit_code == 0, (label, removed.output)
            assert settings.read_bytes() == before, label
            status = json.loads(CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app).output)
            assert status["bindings"] == {}, label

            setup = CliRunner().invoke(
                acp_cmd,
                ["setup", "--client", "zed", "--agent", "kiro", "--activate",
                 "--guard-binary", guard, "--agent-binary", agent],
                obj=app,
            )
            assert setup.exit_code == 0, (label, setup.output)
            servers = json.loads(settings.read_text())["agent_servers"]
            assert servers["My Kiro"] == alias, label
            assert servers["DefenseClaw · Kiro"]["command"] == guard
            removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
            assert removed.exit_code == 0, (label, removed.output)
            assert json.loads(settings.read_text())["agent_servers"] == {"My Kiro": alias}, label
    finally:
        cleanup_app(app, db_path, data_dir)


def test_alias_with_another_runtimes_lock_is_not_this_runtimes(tmp_path, monkeypatch):
    """An alias proven only by another runtime's lock or credential is left alone.

    Setup in a second runtime directory writes a valid lock that binds this
    editor file and pins the same guard. Removal and setup under the current
    runtime must neither delete nor rewrite that alias (nor the settings
    file), and status must not count it as this runtime's binding.
    """
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    other = str((tmp_path / "other-runtime").resolve())
    current_lock = cmd_acp_module._contract_lock_path(data_dir, "zed", "kiro")

    def lock_in(runtime: str) -> str:
        settings.write_text("{}")
        return str(cmd_acp_module._write_contract_lock(
            data_dir=runtime, client="zed", agent="kiro", profile="default", mode="observe",
            guard=guard, agent_executable=agent, client_path=settings.resolve(), managed=False, pin_entries=False,
        ))

    def alias(lock: str, token: str) -> dict:
        return {"command": guard, "args": [
            "--agent", "kiro", "--client", "zed", "--profile", "default", "--mode", "observe",
            "--token-file", token, "--gateway", "http://127.0.0.1:1/api/v1/acp/evaluate",
            "--contract-lock", lock, "--", agent, "acp",
        ]}

    other_token = str(Path(other) / "acp" / ".token")
    current_token = str((Path(data_dir) / "acp" / ".token").resolve())
    variants = {
        # The other runtime's own lock and token: valid, but not this runtime's.
        "other runtime lock": lambda: alias(lock_in(other), other_token),
        # This runtime's lock, but the entry carries another runtime's credential.
        "other runtime token": lambda: (lock_in(other), alias(lock_in(data_dir), other_token))[1],
    }
    if os.name != "nt":
        def writable_lock() -> dict:
            entry = alias(lock_in(data_dir), current_token)
            current_lock.chmod(0o666)
            return entry

        # This runtime's lock path and token, but a lock others can rewrite.
        variants["lock out of custody"] = writable_lock
    try:
        for label, make in variants.items():
            entry = make()
            settings.write_text(json.dumps({"agent_servers": {"Other Kiro": entry}}))
            before = settings.read_bytes()
            removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
            assert removed.exit_code == 0, (label, removed.output)
            assert settings.read_bytes() == before, label

            setup = CliRunner().invoke(
                acp_cmd,
                ["setup", "--client", "zed", "--agent", "kiro", "--activate",
                 "--guard-binary", guard, "--agent-binary", agent],
                obj=app,
            )
            assert setup.exit_code == 0, (label, setup.output)
            servers = json.loads(settings.read_text())["agent_servers"]
            assert servers["Other Kiro"] == entry, label
            assert servers["DefenseClaw · Kiro"]["command"] == guard, label
            if label == "lock out of custody":
                # Setup rewrote the lock owner-only, so the copy now names a
                # lock in this runtime's custody; nothing more to prove here.
                settings.unlink()
                continue
            status = json.loads(CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app).output)
            assert not status["bindings"]["zed/kiro"]["healthy"], (label, status)
            removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
            assert removed.exit_code == 0, (label, removed.output)
            assert json.loads(settings.read_text())["agent_servers"] == {"Other Kiro": entry}, label

        # Control: this runtime's own adopted alias is still this runtime's.
        settings.write_text(json.dumps({"agent_servers": {"My Kiro": {"command": agent, "args": ["acp"]}}}))
        adopted = CliRunner().invoke(
            acp_cmd, ["adopt", "--client", "zed", "--guard-binary", guard, "--yes", "--json-output"], obj=app
        )
        assert adopted.exit_code == 0, adopted.output
        assert list(json.loads(settings.read_text())["agent_servers"]) == ["My Kiro"]
        removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert removed.exit_code == 0, removed.output
        assert not settings.exists()
    finally:
        cleanup_app(app, db_path, data_dir)


def test_alias_backed_by_an_unusable_lock_is_not_owned(tmp_path, monkeypatch):
    """Only the canonical, complete, private lock setup writes proves an alias.

    Each variant names this runtime's lock and token and pins the same guard
    and editor file, but the guard could not start from that lock (or the
    entry reaches it by another path). Removal must leave the alias and the
    settings file byte for byte, warn about it, and status must still answer.
    """
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    runtime = (Path(data_dir) / "acp").resolve()
    lock = runtime / "zed-kiro.contract-lock.json"
    token = str(runtime / ".token")

    def write_lock(mutate=None) -> None:
        settings.write_text("{}")
        cmd_acp_module._write_contract_lock(
            data_dir=data_dir, client="zed", agent="kiro", profile="default", mode="observe",
            guard=guard, agent_executable=agent, client_path=settings.resolve(), managed=False, pin_entries=False,
        )
        if mutate:
            document = json.loads(lock.read_text())
            mutate(document)
            cmd_acp_module.atomic_write_private_bytes(lock, json.dumps(document).encode())

    def alias(lock_value: str, token_value: str = token) -> dict:
        return {"command": guard, "args": [
            "--agent", "kiro", "--client", "zed", "--profile", "default", "--mode", "observe",
            "--token-file", token_value, "--gateway", "http://127.0.0.1:1/api/v1/acp/evaluate",
            "--contract-lock", lock_value, "--", agent, "acp",
        ]}

    def drop(*keys):
        def mutate(document):
            item = document
            for key in keys[:-1]:
                item = item[key]
            del item[keys[-1]]
        return mutate

    def setter(value, *keys):
        def mutate(document):
            item = document
            for key in keys[:-1]:
                item = item[key]
            item[keys[-1]] = value
        return mutate

    variants: dict[str, tuple] = {
        # The path resolves to this lock but is not the path setup writes.
        "dot-dot path": (None, str(runtime / ".." / "acp" / lock.name)),
        "dot-dot token": (None, str(lock), str(runtime / ".." / "acp" / ".token")),
        # Structurally incomplete or wrong-typed locks the guard refuses.
        "no protocol": (drop("protocol"), str(lock)),
        "empty schema pin": (setter("", "protocol", "schema_sha256"), str(lock)),
        "no editor digest": (drop("client", "config_sha256"), str(lock)),
        "no guard digest": (drop("guard", "sha256"), str(lock)),
        "no agent path": (drop("agent", "path"), str(lock)),
        "no mode": (drop("mode"), str(lock)),
        "version 2": (setter(2, "version"), str(lock)),
        "boolean version": (setter(True, "version"), str(lock)),
        "custody not a flag": (setter(0, "guard", "managed_custody"), str(lock)),
        "adopted not a list": (setter("Other Kiro", "client", "adopted_entries"), str(lock)),
    }
    other = tmp_path / "other-runtime" / "acp"
    other.mkdir(parents=True)
    try:
        (other / lock.name).symlink_to(lock)
        # Another runtime's lock path is a symlink to this runtime's lock.
        variants["symlink from another runtime"] = (None, str(other / lock.name))
    except OSError:  # pragma: no cover - Windows without symlink privilege
        pass
    if os.name != "nt":
        # Readable by others: the guard refuses any group or other bit.
        variants["group-readable lock"] = (lambda document: None, str(lock))
    try:
        for label, (mutate, lock_value, *token_value) in variants.items():
            write_lock(mutate)
            if label == "group-readable lock":
                lock.chmod(0o640)
            entry = alias(lock_value, *token_value)
            settings.write_text(json.dumps({"agent_servers": {"Other Kiro": entry}}))
            before = settings.read_bytes()
            status = CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app)
            assert status.exit_code == 0, (label, status.output)
            json.loads(status.output)
            removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
            assert removed.exit_code == 0, (label, removed.output)
            assert settings.read_bytes() == before, label
            assert "Left editor entry 'Other Kiro'" in removed.output, (label, removed.output)

        # Control: the same alias with the canonical, complete, private lock
        # is this runtime's, and removal deletes it (and the file it alone used).
        write_lock()
        settings.write_text(json.dumps({"agent_servers": {"Other Kiro": alias(str(lock))}}))
        removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert removed.exit_code == 0, removed.output
        assert "Left editor entry" not in removed.output
        assert not settings.exists()
    finally:
        cleanup_app(app, db_path, data_dir)


def test_setup_reroutes_only_entries_a_proven_lock_names(tmp_path, monkeypatch):
    """An incomplete lock's adopted_entries must not let setup take over an operator entry."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    lock = (Path(data_dir) / "acp").resolve() / "zed-kiro.contract-lock.json"
    direct = {"command": agent, "args": ["acp"]}
    try:
        settings.write_text("{}")
        cmd_acp_module._write_contract_lock(
            data_dir=data_dir, client="zed", agent="kiro", profile="default", mode="observe",
            guard=guard, agent_executable=agent, client_path=settings.resolve(), managed=False, pin_entries=False,
            adopted_entries=["My Kiro"],
        )
        document = json.loads(lock.read_text())
        del document["protocol"]
        cmd_acp_module.atomic_write_private_bytes(lock, json.dumps(document).encode())
        settings.write_text(json.dumps({"agent_servers": {"My Kiro": direct}}))
        setup = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert setup.exit_code == 0, setup.output
        servers = json.loads(settings.read_text())["agent_servers"]
        assert servers["My Kiro"] == direct
        assert servers["DefenseClaw · Kiro"]["command"] == guard
    finally:
        cleanup_app(app, db_path, data_dir)



def _go_lock_fields() -> dict[str, frozenset[str]]:
    """The JSON fields of the guard's RuntimeContractLock, per object."""
    source = (Path(__file__).parents[2] / "internal" / "acp" / "contract.go").read_text(encoding="utf-8")
    body = source.split("type RuntimeContractLock struct {", 1)[1].split("\n}\n", 1)[0]
    fields: dict[str, frozenset[str]] = {}
    stack: list[set[str]] = [set()]
    for line in body.splitlines():
        stripped = line.strip()
        tag = re.search(r'`json:"([^",]+)', stripped)
        if stripped.endswith("struct {"):
            stack.append(set())
        elif stripped.startswith("}") and tag:
            fields[tag.group(1)] = frozenset(stack.pop())
            stack[-1].add(tag.group(1))
        elif tag:
            stack[-1].add(tag.group(1))
    fields[""] = frozenset(stack[0])
    return fields


def test_ownership_proof_knows_exactly_the_guard_lock_fields():
    """Python's lock proof and the guard's strict decoder must agree on every field."""
    assert cmd_acp_module._LOCK_FIELDS == _go_lock_fields()


def test_lock_with_a_field_the_guard_refuses_proves_nothing(tmp_path, monkeypatch):
    """A lock the guard rejects for an unknown field, at any level, owns no entry.

    Setup must not take over the operator's direct entry such a lock names in
    adopted_entries, and removal must leave a guard alias that names it and
    warn. A lock with an older protocol pin is still this runtime's lock.
    """
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    runtime = (Path(data_dir) / "acp").resolve()
    lock = runtime / "zed-kiro.contract-lock.json"
    direct = {"command": agent, "args": ["acp"]}
    alias = {"command": guard, "args": [
        "--agent", "kiro", "--client", "zed", "--profile", "default", "--mode", "observe",
        "--token-file", str(runtime / ".token"), "--gateway", "http://127.0.0.1:1/api/v1/acp/evaluate",
        "--contract-lock", str(lock), "--", agent, "acp",
    ]}

    def write_lock(*keys: str, value: object = "x") -> None:
        settings.write_text("{}")
        cmd_acp_module._write_contract_lock(
            data_dir=data_dir, client="zed", agent="kiro", profile="default", mode="observe",
            guard=guard, agent_executable=agent, client_path=settings.resolve(), managed=False, pin_entries=False,
            adopted_entries=["My Kiro", "Other Kiro"],
        )
        if keys:
            document = json.loads(lock.read_text())
            item = document
            for key in keys[:-1]:
                item = item[key]
            item[keys[-1]] = value
            cmd_acp_module.atomic_write_private_bytes(lock, json.dumps(document).encode())

    setup_args = ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent]
    remove_args = ["remove", "--client", "zed", "--agent", "kiro"]
    try:
        for keys in (("extra",), ("protocol", "extra"), ("client", "extra"), ("agent", "extra"), ("guard", "extra")):
            write_lock(*keys)
            settings.write_text(json.dumps({"agent_servers": {"My Kiro": direct}}))
            setup = CliRunner().invoke(acp_cmd, setup_args, obj=app)
            assert setup.exit_code == 0, (keys, setup.output)
            servers = json.loads(settings.read_text())["agent_servers"]
            assert servers["My Kiro"] == direct, keys
            assert servers["DefenseClaw · Kiro"]["command"] == guard, keys

            write_lock(*keys)
            settings.write_text(json.dumps({"agent_servers": {"Other Kiro": alias}}))
            before = settings.read_bytes()
            removed = CliRunner().invoke(acp_cmd, remove_args, obj=app)
            assert removed.exit_code == 0, (keys, removed.output)
            assert settings.read_bytes() == before, keys
            assert "Left editor entry 'Other Kiro'" in removed.output, (keys, removed.output)

        # Control: an older protocol pin (a lock from before an upgrade, until
        # acp refresh) still proves the alias, and removal deletes it.
        write_lock("protocol", "schema_version", value="schema-v1.0.0")
        settings.write_text(json.dumps({"agent_servers": {"Other Kiro": alias}}))
        removed = CliRunner().invoke(acp_cmd, remove_args, obj=app)
        assert removed.exit_code == 0, removed.output
        assert "Left editor entry" not in removed.output
        assert not settings.exists()
    finally:
        cleanup_app(app, db_path, data_dir)


def test_alias_launching_other_than_the_locked_agent_is_not_owned(tmp_path, monkeypatch):
    """This runtime's valid lock, token and guard do not prove an alias that launches something else.

    Setup writes exactly its guard options, then -- and the locked agent
    executable with the catalog arguments. An alias that differs (another
    executable or path after --, other or no arguments, another profile or
    mode, an unknown or missing option) is not what setup wrote: removal
    leaves it and its settings file byte for byte and warns, and setup does
    not rewrite it.
    """
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    other_agent = _binary(tmp_path / "other-agent")
    (tmp_path / "sub").mkdir()
    runtime = (Path(data_dir) / "acp").resolve()
    lock = runtime / "zed-kiro.contract-lock.json"
    base = {
        "--agent": "kiro", "--client": "zed", "--profile": "default", "--mode": "observe",
        "--token-file": str(runtime / ".token"), "--gateway": "http://127.0.0.1:1/api/v1/acp/evaluate",
        "--contract-lock": str(lock),
    }

    def alias(tail=(agent, "acp"), drop=(), **changes) -> dict:
        options = {**base, **{f"--{key.replace('_', '-')}": value for key, value in changes.items()}}
        for key in drop:
            del options[key]
        return {"command": guard, "args": [*(item for pair in options.items() for item in pair), "--", *tail]}

    variants = {
        "another executable": alias(tail=(other_agent, "acp")),
        "same file by another path": alias(tail=(str(tmp_path / "sub" / ".." / "kiro-cli"), "acp")),
        "extra argument": alias(tail=(agent, "acp", "--trust-all-tools")),
        "no catalog arguments": alias(tail=(agent,)),
        "no command": alias(tail=()),
        "another profile": alias(profile="other"),
        "another mode": alias(mode="action"),
        "unknown option": alias(extra="x"),
        "no gateway": alias(drop=("--gateway",)),
    }
    setup_args = ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent]
    remove_args = ["remove", "--client", "zed", "--agent", "kiro"]

    def write_lock() -> None:
        settings.write_text("{}")
        cmd_acp_module._write_contract_lock(
            data_dir=data_dir, client="zed", agent="kiro", profile="default", mode="observe",
            guard=guard, agent_executable=agent, client_path=settings.resolve(), managed=False, pin_entries=False,
        )

    try:
        for label, entry in variants.items():
            write_lock()
            settings.write_text(json.dumps({"agent_servers": {"Other Kiro": entry}}))
            before = settings.read_bytes()
            removed = CliRunner().invoke(acp_cmd, remove_args, obj=app)
            assert removed.exit_code == 0, (label, removed.output)
            assert settings.read_bytes() == before, label
            assert "Left editor entry 'Other Kiro'" in removed.output, (label, removed.output)

            write_lock()
            settings.write_text(json.dumps({"agent_servers": {"Other Kiro": entry}}))
            setup = CliRunner().invoke(acp_cmd, setup_args, obj=app)
            assert setup.exit_code == 0, (label, setup.output)
            servers = json.loads(settings.read_text())["agent_servers"]
            assert servers["Other Kiro"] == entry, label
            assert servers["DefenseClaw · Kiro"]["command"] == guard, label
            removed = CliRunner().invoke(acp_cmd, remove_args, obj=app)
            assert removed.exit_code == 0, (label, removed.output)
            assert json.loads(settings.read_text())["agent_servers"] == {"Other Kiro": entry}, label

        # Control: the exact launch setup writes is this runtime's alias.
        write_lock()
        settings.write_text(json.dumps({"agent_servers": {"Other Kiro": alias()}}))
        removed = CliRunner().invoke(acp_cmd, remove_args, obj=app)
        assert removed.exit_code == 0, removed.output
        assert "Left editor entry" not in removed.output
        assert not settings.exists()
    finally:
        cleanup_app(app, db_path, data_dir)


def test_missing_editor_settings_is_a_binding_problem(tmp_path, monkeypatch):
    """A binding whose editor file is gone is unhealthy, with a repair, not a crash."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    setup = ["setup", "--client", "zed", "--agent", "kiro", "--profile", "locked", "--activate",
             "--guard-binary", guard, "--agent-binary", agent]
    try:
        for verify in (["verify"], ["verify", "--client", "zed", "--agent", "kiro"]):
            result = CliRunner().invoke(acp_cmd, setup, obj=app)
            assert result.exit_code == 0, result.output
            settings.unlink()

            status = CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app)
            assert status.exit_code == 0, status.output
            binding = json.loads(status.output)["bindings"]["zed/kiro"]
            assert not binding["healthy"]
            assert f"editor settings file is missing: {settings}" in binding["problems"]
            assert (binding["profile"], binding["mode"]) == ("locked", "action")
            text = CliRunner().invoke(acp_cmd, ["status"], obj=app)
            assert text.exit_code == 0 and "NEEDS ATTENTION" in text.output, text.output

            failed = CliRunner().invoke(acp_cmd, verify, obj=app)
            assert failed.exit_code != 0
            assert not isinstance(failed.exception, FileNotFoundError), failed.exception
            assert "editor settings file is missing" in failed.output, failed.output
            repair = _repair_args(failed.output)
            assert "--activate" in repair and "locked" in repair, repair
            repaired = CliRunner().invoke(acp_cmd, repair, obj=app)
            assert repaired.exit_code == 0, repaired.output
            assert CliRunner().invoke(acp_cmd, verify, obj=app).exit_code == 0

        # An explicit pair whose editor path is not a file is reported, not raised.
        settings.unlink()
        settings.mkdir()
        failed = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert failed.exit_code != 0
        assert "editor settings file cannot be used" in failed.output, failed.output
        assert "; run " in failed.output, failed.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_bypassed_adopted_entry_stays_in_status_and_verify(tmp_path, monkeypatch):
    """Pointing an adopted entry back at the agent must not make the binding vanish."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    opencode = _binary(tmp_path / "opencode")
    direct = {"command": agent, "args": ["acp"], "env": {"KEEP": "me"}}
    lock_path = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
    try:
        for bypass in ("direct", "deleted"):
            settings.write_text(json.dumps({"agent_servers": {"My Kiro": direct}}))
            adopted = CliRunner().invoke(
                acp_cmd,
                ["adopt", "--client", "zed", "--guard-binary", guard, "--activate", "--yes", "--json-output"],
                obj=app,
            )
            assert adopted.exit_code == 0, adopted.output
            assert json.loads(lock_path.read_text())["client"]["adopted_entries"] == ["My Kiro"]
            assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code == 0

            document = json.loads(settings.read_text())
            if bypass == "direct":
                document["agent_servers"]["My Kiro"] = direct
            else:
                del document["agent_servers"]["My Kiro"]
            settings.write_text(json.dumps(document))

            status = json.loads(CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app).output)
            binding = status["bindings"]["zed/kiro"]
            assert binding["healthy"] is False and binding["mode"] == "action", bypass
            assert any("'My Kiro' no longer launches the DefenseClaw guard" in p for p in binding["problems"])
            verified = CliRunner().invoke(acp_cmd, ["verify"], obj=app)
            assert verified.exit_code != 0 and "zed/kiro" in verified.output, verified.output
            assert "--activate" in _repair_args(verified.output)

            # A bypassed pair still counts as using its profile.
            shared = CliRunner().invoke(
                acp_cmd,
                ["setup", "--client", "zed", "--agent", "opencode", "--guard-binary", guard,
                 "--agent-binary", opencode],
                obj=app,
            )
            assert shared.exit_code != 0 and "zed/kiro" in shared.output, shared.output
            assert app.cfg.acp.profiles["default"].mode == "action"

            repaired = CliRunner().invoke(acp_cmd, _repair_args(verified.output), obj=app)
            assert repaired.exit_code == 0, repaired.output
            servers = json.loads(settings.read_text())["agent_servers"]
            if bypass == "direct":
                # Setup does not take ownership of an entry now launching directly.
                assert servers["My Kiro"] == direct
                assert servers["DefenseClaw · Kiro"]["command"] == guard
                assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code != 0
                explicit = CliRunner().invoke(
                    acp_cmd, ["adopt", "--client", "zed", "--guard-binary", guard,
                              "--activate", "--yes", "--json-output"], obj=app,
                )
                assert explicit.exit_code == 0, explicit.output
                servers = json.loads(settings.read_text())["agent_servers"]
                assert servers["My Kiro"]["command"] == guard and servers["My Kiro"]["env"] == {"KEEP": "me"}
                assert "DefenseClaw · Kiro" not in servers
            else:
                assert servers["DefenseClaw · Kiro"]["command"] == guard
            assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code == 0

            removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
            assert removed.exit_code == 0, removed.output
            assert not settings.exists()

        # A configured binding whose editor entry and lock are both gone is still listed.
        app.cfg.acp.bindings["zed/kiro"] = ACPBinding(enabled=True, profile="default")
        status = json.loads(CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app).output)
        assert status["bindings"]["zed/kiro"]["healthy"] is False
        assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code != 0
    finally:
        cleanup_app(app, db_path, data_dir)


@pytest.mark.parametrize("entry_names", [[], ["My Kiro", "Kiro (2)"]], ids=["reserved", "adopted-and-numbered"])
def test_only_setup_moves_a_legacy_whole_file_pin_to_entry_pins(tmp_path, monkeypatch, entry_names):
    # W7 loop 1: a lock from 1.0.3 or older pins the whole settings file. The
    # upgrade's acp refresh re-pins only the guard, so the binding stays strict
    # until the setup command verify prints runs for it, once per binding.
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard_path = tmp_path / "bin" / "defenseclaw-acp"
    guard_path.parent.mkdir()
    guard = _binary(guard_path)
    kiro = _binary(tmp_path / "kiro-cli")
    cursor = _binary(tmp_path / "cursor-agent")
    settings = _zed_settings(tmp_path)
    locks = {agent: Path(data_dir) / "acp" / f"zed-{agent}.contract-lock.json" for agent in ("kiro", "cursor")}
    runner = CliRunner()

    def verify(agent):
        return runner.invoke(acp_cmd, ["verify", "--client", "zed", "--agent", agent], obj=app)

    def client_pin(agent):
        return json.loads(locks[agent].read_text())["client"]

    def theme(value):
        document = json.loads(settings.read_text())
        document["theme"] = value
        settings.write_text(json.dumps(document))

    try:
        if entry_names:
            settings.parent.mkdir(parents=True)
            settings.write_text(json.dumps({"agent_servers": {
                name: {"command": kiro, "args": ["acp"]} for name in entry_names
            }}))
            args = ["adopt", "--client", "zed", "--guard-binary", guard, "--yes", "--json-output"]
        else:
            args = ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", kiro]
        result = runner.invoke(acp_cmd, args, obj=app)
        assert result.exit_code == 0, result.output
        result = runner.invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "cursor", "--guard-binary", guard, "--agent-binary", cursor],
            obj=app,
        )
        assert result.exit_code == 0, result.output
        # What an older release wrote: the whole-file digest.
        for lock in locks.values():
            document = json.loads(lock.read_text())
            document["client"]["config_sha256"] = cmd_acp_module._sha256_file(str(settings))
            lock.write_text(json.dumps(document))
        assert verify("kiro").exit_code == 0 and verify("cursor").exit_code == 0

        # The upgrade replaces the guard and the installer runs acp refresh.
        guard_path.write_bytes(b"upgraded-guard")
        legacy = {agent: client_pin(agent) for agent in locks}
        result = runner.invoke(acp_cmd, ["refresh"], obj=app)
        assert result.exit_code == 0, result.output
        assert "zed/kiro" in result.output and "zed/cursor" in result.output
        assert {agent: client_pin(agent) for agent in locks} == legacy
        assert verify("kiro").exit_code == 0 and verify("cursor").exit_code == 0

        # The pin is still the whole file: a theme change fails verification.
        theme("Ayu")
        for agent in locks:
            drifted = verify(agent)
            assert drifted.exit_code != 0 and "client configuration digest has drifted" in drifted.output
        assert runner.invoke(acp_cmd, ["refresh"], obj=app).output == ""
        assert {agent: client_pin(agent) for agent in locks} == legacy
        assert verify("kiro").exit_code != 0

        # The remedy the docs name: the setup command verify prints.
        result = runner.invoke(acp_cmd, _repair_args(verify("kiro").output), obj=app)
        assert result.exit_code == 0, result.output
        pin = client_pin("kiro")
        assert pin["config_sha256"].startswith(cmd_acp_module._ENTRY_DIGEST_PREFIX)
        assert sorted(pin.get("adopted_entries", [])) == sorted(entry_names)
        theme("One Dark")
        assert verify("kiro").exit_code == 0, verify("kiro").output

        # Each binding needs its own setup: the other lock is still a file pin.
        assert not client_pin("cursor")["config_sha256"].startswith(cmd_acp_module._ENTRY_DIGEST_PREFIX)
        theme("Ayu")
        drifted = verify("cursor")
        assert drifted.exit_code != 0 and "client configuration digest has drifted" in drifted.output
        result = runner.invoke(acp_cmd, _repair_args(drifted.output), obj=app)
        assert result.exit_code == 0, result.output
        assert client_pin("cursor")["config_sha256"].startswith(cmd_acp_module._ENTRY_DIGEST_PREFIX)
        theme("Solarized")
        assert verify("kiro").exit_code == 0 and verify("cursor").exit_code == 0
    finally:
        cleanup_app(app, db_path, data_dir)


def test_docs_name_setup_not_refresh_for_legacy_whole_file_pins():
    # W7 loop 1: the reference and changelog said acp refresh moved a legacy
    # whole-file pin to entry pins; refresh re-pins only the guard.
    root = Path(__file__).resolve().parents[2]
    for relative in (
        "docs-site/content/docs/reference/apis/acp-guard.mdx",
        "docs-site/content/docs/reference/commands/cli.mdx",
        "CHANGELOG.md",
    ):
        text = (root / relative).read_text(encoding="utf-8")
        units = [" ".join(unit.split()) for unit in re.split(r"\n\s*\n|\n(?=[-|] )", text)]
        legacy = [unit for unit in units if "whole settings file" in unit or "whole-file pin" in unit]
        assert legacy, relative
        for unit in legacy:
            assert "acp setup" in unit, (relative, unit)
            for sentence in re.split(r"(?<=[.;])\s+", unit):
                if "refresh" in sentence and not re.search(r"only the guard|do not change|does not change", sentence):
                    assert not re.search(r"until|entry pins|pin only|migrat|convert|preference", sentence), (
                        relative, sentence,
                    )
        assert not re.search(r"until (you run `defenseclaw acp refresh`|refreshed)", text), relative


def _direct_alias_variants(tmp_path: Path, agent: str) -> dict:
    """Second editor entries that start Kiro without the guard (W7 loop 2)."""
    tools = tmp_path / "tools"
    tools.mkdir(exist_ok=True)

    def copy() -> dict:
        target = tools / "assistant-copy"
        target.write_bytes(Path(agent).read_bytes())
        target.chmod(0o700)
        return {"command": str(target), "args": ["acp"]}

    def script() -> dict:
        target = tools / "wrapper.sh"
        target.write_text('#!/bin/sh\nexec kiro-cli acp "$@"\n')
        target.chmod(0o700)
        return {"command": str(target)}

    def renamed_on_path() -> dict:
        # Windows finds a bare name on PATH only with a PATHEXT suffix.
        target = tools / ("k2.exe" if os.name == "nt" else "k2")
        target.write_bytes(Path(agent).read_bytes())
        target.chmod(0o700)
        return {"command": "env", "args": ["k2", "acp"]}

    def guard_lookalike() -> dict:
        wrapper = tools / "other" / "defenseclaw-acp"
        wrapper.parent.mkdir(exist_ok=True)
        wrapper.write_bytes(b"not the pinned guard")
        wrapper.chmod(0o700)
        return {"command": str(wrapper), "args": ["--agent", "kiro", "--client", "zed", "--", agent, "acp"]}

    variants = {
        "catalog command": lambda: {"command": "kiro-cli", "args": ["acp"]},
        "pinned path, other args": lambda: {"command": agent, "args": ["acp", "--trust-all-tools"]},
        "case and suffix": lambda: {"command": "KIRO-CLI.EXE", "args": ["ACP"]},
        "windows path": lambda: {"command": "C:\\Tools\\Kiro\\Kiro-Cli.cmd", "args": ["acp"]},
        "copy of the pinned binary": copy,
        "env wrapper": lambda: {"command": "env", "args": ["KIRO_LOG=1", "kiro-cli", "acp"]},
        "inline shell": lambda: {"command": "sh", "args": ["-c", "exec kiro-cli acp"]},
        "path in env": lambda: {"command": "sh", "args": ["-c", 'exec "$K" acp'], "env": {"K": agent}},
        "renamed binary on PATH": renamed_on_path,
        "wrapper script": script,
        "guard look-alike": guard_lookalike,
        "registry entry": lambda: {"type": "registry"},
        "preferences only": lambda: {"default_mode": "write"},
    }
    if os.name != "nt":
        def link() -> dict:
            target = tools / "assistant-link"
            target.unlink(missing_ok=True)
            target.symlink_to(agent)
            return {"command": str(target), "args": ["acp"]}

        variants["link under another name"] = link
    return variants


@pytest.mark.parametrize("entry_names", [[], ["My Kiro"]], ids=["reserved", "adopted"])
def test_verify_rejects_a_direct_agent_alias_beside_the_guarded_entry(tmp_path, monkeypatch, entry_names):
    # W7 loop 2: entry pins cover only the guarded entries, so a second
    # entry that starts Kiro directly left verify green while Zed could
    # launch Kiro unmediated. The whole-file pin in 1.0.3 caught it.
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    monkeypatch.setenv("PATH", str(tmp_path / "tools") + os.pathsep + os.environ.get("PATH", ""))
    try:
        initial = {"agent_servers": {}}
        for name in entry_names:
            initial["agent_servers"][name] = {"command": agent, "args": ["acp"]}
        settings.write_text(json.dumps(initial))
        args = ["setup", "--client", "zed", "--agent", "kiro", "--activate", "--guard-binary", guard,
                "--agent-binary", agent]
        if entry_names:
            args = ["adopt", "--client", "zed", "--guard-binary", guard, "--activate", "--yes", "--json-output"]
        configured = CliRunner().invoke(acp_cmd, args, obj=app)
        assert configured.exit_code == 0, configured.output
        guarded = json.loads(settings.read_text())
        assert set(guarded["agent_servers"]) == set(entry_names or ["DefenseClaw · Kiro"])
        # Zed's editor-owned preference remains outside the launch pin.
        for name in entry_names or ["DefenseClaw · Kiro"]:
            guarded["agent_servers"][name]["default_mode"] = "write"
        settings.write_text(json.dumps(guarded))
        verified = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert verified.exit_code == 0, verified.output

        for label, make in _direct_alias_variants(tmp_path, agent).items():
            name = "Kiro" if label in {"registry entry", "preferences only"} else "Fast Assistant"
            document = json.loads(json.dumps(guarded))
            document["agent_servers"][name] = make()
            settings.write_text(json.dumps(document))
            verified = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
            assert verified.exit_code != 0, (label, verified.output)
            assert f"editor entry {name!r} can start kiro without the DefenseClaw guard" in verified.output, label
            status = json.loads(CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app).output)
            assert status["bindings"]["zed/kiro"]["healthy"] is False, label

        # The remedy verify names: adopt routes the direct entry through the guard.
        document = json.loads(json.dumps(guarded))
        document["agent_servers"]["Fast Assistant"] = {"command": agent, "args": ["acp"]}
        settings.write_text(json.dumps(document))
        adopted = CliRunner().invoke(
            acp_cmd, ["adopt", "--client", "zed", "--guard-binary", guard, "--activate", "--yes", "--json-output"],
            obj=app,
        )
        assert adopted.exit_code == 0, adopted.output
        assert json.loads(settings.read_text())["agent_servers"]["Fast Assistant"]["command"] == guard
        verified = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert verified.exit_code == 0, verified.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_verify_distinguishes_a_generic_agent_command_from_preferences(tmp_path, monkeypatch):
    # Cursor's ACP command is the bare word "agent". A Zed preference using
    # that word does not change the guarded launch; a direct entry does.
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    cursor = _binary(tmp_path / "agent")
    try:
        settings.write_text(json.dumps({"agent_servers": {}}))
        configured = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "cursor", "--guard-binary", guard, "--agent-binary", cursor],
            obj=app,
        )
        assert configured.exit_code == 0, configured.output
        verify = ["verify", "--client", "zed", "--agent", "cursor"]
        guarded = json.loads(settings.read_text())
        guarded["agent_servers"]["DefenseClaw · Cursor"]["default_mode"] = "agent"
        settings.write_text(json.dumps(guarded))
        assert CliRunner().invoke(acp_cmd, verify, obj=app).exit_code == 0
        document = json.loads(json.dumps(guarded))
        document["agent_servers"]["OpenCode"] = {"command": "opencode", "args": ["acp"], "default_mode": "agent"}
        settings.write_text(json.dumps(document))
        assert CliRunner().invoke(acp_cmd, verify, obj=app).exit_code != 0
        for entry in ({"command": "agent", "args": ["acp"]}, {"command": "env", "args": ["agent", "acp"]},
                      {"command": "Agent.exe"}):
            document = json.loads(json.dumps(guarded))
            document["agent_servers"]["Assistant"] = entry
            settings.write_text(json.dumps(document))
            verified = CliRunner().invoke(acp_cmd, verify, obj=app)
            assert verified.exit_code != 0 and "'Assistant' can start cursor" in verified.output, entry
    finally:
        cleanup_app(app, db_path, data_dir)


def test_verify_rejects_unknown_zed_launch_entries(tmp_path, monkeypatch):
    """A new opaque editor launch is unverified even if its bytes hide the agent name."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    opaque = _binary(tmp_path / "unlabeled-bridge")
    try:
        setup = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--activate",
             "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert setup.exit_code == 0, setup.output
        base = json.loads(settings.read_text())
        for name, entry in (
            ("Opaque", {"command": opaque, "args": ["serve"]}),
            ("Registry alias", {"type": "registry", "source": "local"}),
            ("Malformed type", {"type": ["custom"], "command": "opencode", "args": ["acp"]}),
            ("Unrecognized shape", {"command": "opencode", "args": ["acp"], "launch_with": opaque}),
        ):
            document = json.loads(json.dumps(base))
            document["agent_servers"][name] = entry
            settings.write_text(json.dumps(document))
            verified = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
            assert verified.exit_code != 0 and name in verified.output, (name, verified.output)
            status = json.loads(CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app).output)
            assert not status["bindings"]["zed/kiro"]["healthy"], name
        tools = tmp_path / "tools"
        tools.mkdir()
        copy = tools / ("opencode.exe" if os.name == "nt" else "opencode")
        copy.write_bytes(Path(agent).read_bytes())
        copy.chmod(0o700)
        monkeypatch.setenv("PATH", str(tools) + os.pathsep + os.environ.get("PATH", ""))
        document = json.loads(json.dumps(base))
        document["agent_servers"]["Catalog alias"] = {"command": "opencode", "args": ["acp"]}
        settings.write_text(json.dumps(document))
        verified = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert verified.exit_code != 0 and "Catalog alias" in verified.output, verified.output

        # A catalog command can resolve to an opaque replacement on PATH.
        # Its different digest does not prove which agent it starts.
        copy.write_bytes(b"opaque-launcher")
        settings.write_text(json.dumps(document))
        verified = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert verified.exit_code != 0 and "Catalog alias" in verified.output, verified.output

        # A second lock can claim a different pair while pointing at the
        # protected agent's executable. Its guard is not this binding.
        settings.write_text(json.dumps(base))
        other_lock = cmd_acp_module._write_contract_lock(
            data_dir=str(data_dir), client="zed", agent="cursor", profile="default", mode="observe",
            guard=guard, agent_executable=agent, client_path=settings, managed=False, pin_entries=False,
        )
        document = json.loads(json.dumps(base))
        document["agent_servers"]["Other guard"] = {"command": guard, "args": [
            "--agent", "cursor", "--client", "zed", "--profile", "default", "--mode", "observe",
            "--token-file", str((Path(data_dir) / "acp" / ".token").resolve()),
            "--gateway", "http://127.0.0.1:1/api/v1/acp/evaluate",
            "--contract-lock", str(other_lock), "--", agent, "acp",
        ]}
        settings.write_text(json.dumps(document))
        verified = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert verified.exit_code != 0 and "Other guard" in verified.output, verified.output

        # A private lock is not proof that an unrelated executable is the
        # installed guard. A look-alike can start Kiro directly while
        # claiming to guard Cursor.
        fake_guard = _binary(tmp_path / "another-acp-guard")
        cursor = _binary(tmp_path / "cursor-agent")
        other_lock = cmd_acp_module._write_contract_lock(
            data_dir=str(data_dir), client="zed", agent="cursor", profile="default", mode="observe",
            guard=fake_guard, agent_executable=cursor, client_path=settings, managed=False, pin_entries=False,
        )
        document = json.loads(json.dumps(base))
        document["agent_servers"]["Other guard"] = {"command": fake_guard, "args": [
            "--agent", "cursor", "--client", "zed", "--profile", "default", "--mode", "observe",
            "--token-file", str((Path(data_dir) / "acp" / ".token").resolve()),
            "--gateway", "http://127.0.0.1:1/api/v1/acp/evaluate",
            "--contract-lock", str(other_lock), "--", cursor, "acp",
        ]}
        settings.write_text(json.dumps(document))
        verified = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert verified.exit_code != 0 and "Other guard" in verified.output, verified.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_setup_cannot_repin_an_unknown_launch_field_on_its_guarded_entry(tmp_path, monkeypatch):
    """A repeated setup cannot turn a second editor launch route into a healthy pin."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    try:
        args = ["setup", "--client", "zed", "--agent", "kiro", "--activate",
                "--guard-binary", guard, "--agent-binary", agent]
        configured = CliRunner().invoke(acp_cmd, args, obj=app)
        assert configured.exit_code == 0, configured.output
        document = json.loads(settings.read_text())
        document["agent_servers"]["DefenseClaw · Kiro"]["launch_with"] = agent
        settings.write_text(json.dumps(document))
        lock_path = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
        pinned_before = lock_path.read_bytes()

        repeated = CliRunner().invoke(acp_cmd, args, obj=app)
        assert repeated.exit_code != 0, repeated.output
        assert lock_path.read_bytes() == pinned_before
        verified = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert verified.exit_code != 0 and "unknown launch fields" in verified.output, verified.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_setup_does_not_claim_a_formerly_adopted_direct_entry(tmp_path, monkeypatch):
    """A direct adopted alias remains operator-owned until explicit adoption or removal."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    direct = {"command": agent, "args": ["acp"], "env": {"KEEP": "me"}}
    settings.write_text(json.dumps({"agent_servers": {"My Kiro": direct}}))
    try:
        adopted = CliRunner().invoke(
            acp_cmd, ["adopt", "--client", "zed", "--guard-binary", guard, "--activate", "--yes"], obj=app,
        )
        assert adopted.exit_code == 0, adopted.output
        document = json.loads(settings.read_text())
        document["agent_servers"]["My Kiro"] = direct
        settings.write_text(json.dumps(document))
        setup = CliRunner().invoke(
            acp_cmd, ["setup", "--client", "zed", "--agent", "kiro", "--activate",
                      "--guard-binary", guard, "--agent-binary", agent], obj=app,
        )
        assert setup.exit_code == 0, setup.output
        servers = json.loads(settings.read_text())["agent_servers"]
        assert servers["My Kiro"] == direct
        assert servers["DefenseClaw · Kiro"]["command"] == guard
        verified = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert verified.exit_code != 0 and "My Kiro" in verified.output, verified.output
    finally:
        cleanup_app(app, db_path, data_dir)


@pytest.mark.parametrize("operation", ["setup", "remove"])
def test_other_binding_cannot_repin_drifted_legacy_client_lock(tmp_path, monkeypatch, operation):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agents = {name: _binary(tmp_path / ("kiro-cli" if name == "kiro" else "agent"))
              for name in ("kiro", "cursor")}
    runner = CliRunner()
    try:
        for name in agents:
            result = runner.invoke(
                acp_cmd, ["setup", "--client", "zed", "--agent", name, "--guard-binary", guard,
                          "--agent-binary", agents[name]], obj=app,
            )
            assert result.exit_code == 0, result.output
        legacy_lock = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
        document = json.loads(legacy_lock.read_text())
        document["client"]["config_sha256"] = cmd_acp_module._sha256_file(str(settings))
        cmd_acp_module.atomic_write_private_bytes(legacy_lock, json.dumps(document).encode())
        changed = json.loads(settings.read_text())
        changed["agent_servers"]["DefenseClaw · Kiro"]["env"]["CHANGED"] = "yes"
        settings.write_text(json.dumps(changed))
        before = (settings.read_bytes(), legacy_lock.read_bytes())
        if operation == "setup":
            args = ["setup", "--client", "zed", "--agent", "cursor", "--guard-binary", guard,
                    "--agent-binary", agents["cursor"]]
        else:
            args = ["remove", "--client", "zed", "--agent", "cursor"]
        result = runner.invoke(acp_cmd, args, obj=app)
        assert result.exit_code == 0, result.output
        assert legacy_lock.read_bytes() == before[1]
        verified = runner.invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert verified.exit_code != 0 and "digest has drifted" in verified.output, verified.output
    finally:
        cleanup_app(app, db_path, data_dir)


@pytest.mark.parametrize("operation", ["setup", "remove"])
def test_valid_legacy_client_pin_follows_another_binding_change(tmp_path, monkeypatch, operation):
    """A sound 1.0.0-1.0.3 file pin survives a legitimate edit to another pair."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agents = {name: _binary(tmp_path / ("kiro-cli" if name == "kiro" else "agent"))
              for name in ("kiro", "cursor")}
    runner = CliRunner()
    try:
        for name in agents:
            setup = runner.invoke(
                acp_cmd, ["setup", "--client", "zed", "--agent", name, "--guard-binary", guard,
                          "--agent-binary", agents[name]], obj=app,
            )
            assert setup.exit_code == 0, setup.output
        lock_path = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
        legacy = json.loads(lock_path.read_text())
        legacy["client"]["config_sha256"] = cmd_acp_module._sha256_file(str(settings))
        cmd_acp_module.atomic_write_private_bytes(lock_path, json.dumps(legacy).encode())
        args = [operation, "--client", "zed", "--agent", "cursor"]
        if operation == "setup":
            args += ["--guard-binary", guard, "--agent-binary", agents["cursor"]]
        result = runner.invoke(acp_cmd, args, obj=app)
        assert result.exit_code == 0, result.output
        current = json.loads(lock_path.read_text())
        assert current["client"]["config_sha256"] == cmd_acp_module._sha256_file(str(settings))
        assert runner.invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app).exit_code == 0
    finally:
        cleanup_app(app, db_path, data_dir)


@pytest.mark.parametrize("target_names", [[], ["My Kiro"]], ids=["reserved", "adopted"])
def test_verify_accepts_another_bindings_adopted_entry_only_under_its_own_pin(tmp_path, monkeypatch, target_names):
    """Another pair's adopted entry keeps operator env; its own pin, not this binding, proves it."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    kiro = _binary(tmp_path / "kiro-cli")
    cursor = _binary(tmp_path / ("agent.exe" if os.name == "nt" else "agent"))
    servers = {"My Cursor": {"command": cursor, "args": ["acp"], "env": {"CURSOR_LOG": "1"}}}
    if target_names:
        servers["My Kiro"] = {"command": kiro, "args": ["acp"], "env": {"KIRO_LOG": "1"}}
    settings.write_text(json.dumps({"agent_servers": servers}))
    runner = CliRunner()

    def verify(agent):
        return runner.invoke(acp_cmd, ["verify", "--client", "zed", "--agent", agent], obj=app)

    try:
        adopted = runner.invoke(
            acp_cmd, ["adopt", "--client", "zed", "--guard-binary", guard, "--activate", "--yes"], obj=app,
        )
        assert adopted.exit_code == 0, adopted.output
        if not target_names:
            setup = runner.invoke(
                acp_cmd, ["setup", "--client", "zed", "--agent", "kiro", "--activate",
                          "--guard-binary", guard, "--agent-binary", kiro], obj=app,
            )
            assert setup.exit_code == 0, setup.output
        document = json.loads(settings.read_text())
        assert document["agent_servers"]["My Cursor"]["env"] == {"CURSOR_LOG": "1"}
        document["theme"] = "Ayu"
        settings.write_text(json.dumps(document))
        for agent in ("kiro", "cursor"):
            assert verify(agent).exit_code == 0, (agent, verify(agent).output)
        assert runner.invoke(acp_cmd, ["verify"], obj=app).exit_code == 0

        # The env belongs to the cursor binding's own launch fields. Once its
        # own pin no longer proves them, cursor fails, and kiro cannot treat
        # that unproven launch as mediated either.
        drifted = json.loads(json.dumps(document))
        drifted["agent_servers"]["My Cursor"]["env"]["LD_PRELOAD"] = str(tmp_path / "x.so")
        settings.write_text(json.dumps(drifted))
        assert verify("cursor").exit_code != 0
        result = verify("kiro")
        assert result.exit_code != 0 and "My Cursor" in result.output, result.output

        # A guarded entry the cursor pin does not cover (a copy under a new
        # name) is not proven by that pin, so its env is unproven too.
        copied = json.loads(json.dumps(document))
        copied["agent_servers"]["Cursor copy"] = copied["agent_servers"]["My Cursor"]
        settings.write_text(json.dumps(copied))
        result = verify("kiro")
        assert result.exit_code != 0 and "Cursor copy" in result.output, result.output
        settings.write_text(json.dumps(document))
        assert verify("kiro").exit_code == 0
    finally:
        cleanup_app(app, db_path, data_dir)


def _break_lock(lock: Path, defect: str) -> None:
    if defect == "missing":
        lock.unlink()
    elif defect == "symlink":
        target = lock.with_name("elsewhere.json")
        target.write_bytes(lock.read_bytes())
        lock.unlink()
        lock.symlink_to(target)
    elif defect == "unreadable":
        cmd_acp_module.atomic_write_private_bytes(lock, b"{not json")
    elif defect == "not-private":
        lock.chmod(0o644)
    else:
        document = json.loads(lock.read_text())
        if defect == "incomplete":
            del document["guard"]["sha256"]
        elif defect == "unknown-field":
            document["client"]["extra"] = "x"
        elif defect == "identity":
            document["agent"]["id"] = "cursor"
        cmd_acp_module.atomic_write_private_bytes(lock, json.dumps(document).encode())


@pytest.mark.parametrize("operation", ["setup", "remove"])
@pytest.mark.parametrize(
    "defect", ["missing", "symlink", "unreadable", "not-private", "incomplete", "unknown-field", "identity"],
)
def test_another_pairs_unproven_lock_does_not_block_this_pairs_write(tmp_path, monkeypatch, operation, defect):
    """Setup and remove check only the pair being written; the broken pair stays broken."""
    if os.name == "nt" and defect in {"symlink", "not-private"}:
        pytest.skip("POSIX lock custody")
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agents = {name: _binary(tmp_path / ("kiro-cli" if name == "kiro" else "agent"))
              for name in ("kiro", "cursor")}
    runner = CliRunner()
    try:
        for name in agents:
            result = runner.invoke(
                acp_cmd, ["setup", "--client", "zed", "--agent", name, "--guard-binary", guard,
                          "--agent-binary", agents[name]], obj=app,
            )
            assert result.exit_code == 0, result.output
        lock = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
        _break_lock(lock, defect)
        before = (lock.is_symlink(), lock.read_bytes() if lock.exists() else b"")
        args = [operation, "--client", "zed", "--agent", "cursor"]
        if operation == "setup":
            args += ["--guard-binary", guard, "--agent-binary", agents["cursor"]]
        result = runner.invoke(acp_cmd, args, obj=app)
        assert result.exit_code == 0, result.output
        assert (lock.is_symlink(), lock.read_bytes() if lock.exists() else b"") == before
        servers = json.loads(settings.read_text())["agent_servers"]
        assert ("DefenseClaw · Cursor" in servers) == (operation == "setup")
        assert "DefenseClaw · Kiro" in servers
        verified = runner.invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert verified.exit_code != 0 and "zed/kiro" in verified.output, verified.output
        if operation == "setup":
            # Fail closed: the kiro entry's launch is unknown while its lock
            # is unproven, so cursor names it until kiro's own setup.
            verified = runner.invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "cursor"], obj=app)
            assert verified.exit_code != 0 and "DefenseClaw · Kiro" in verified.output, verified.output
        if lock.is_symlink():
            lock.unlink()
        repaired = runner.invoke(
            acp_cmd, ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard,
                      "--agent-binary", agents["kiro"]], obj=app,
        )
        assert repaired.exit_code == 0, repaired.output
        assert runner.invoke(acp_cmd, ["verify"], obj=app).exit_code == 0
    finally:
        cleanup_app(app, db_path, data_dir)


@pytest.mark.parametrize("entry_names", [[], ["My Kiro"]], ids=["reserved", "adopted"])
def test_unpinned_copy_of_a_guarded_entry_verifies_only_without_its_own_launch_fields(
    tmp_path, monkeypatch, entry_names
):
    """A same-pair copy is outside its binding's entry pin, so it cannot carry env or another gateway."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    kiro = _binary(tmp_path / "kiro-cli")
    runner = CliRunner()
    if entry_names:
        settings.write_text(json.dumps({"agent_servers": {"My Kiro": {"command": kiro, "args": ["acp"]}}}))
        args = ["adopt", "--client", "zed", "--guard-binary", guard, "--activate", "--yes"]
        guarded = "My Kiro"
    else:
        args = ["setup", "--client", "zed", "--agent", "kiro", "--activate",
                "--guard-binary", guard, "--agent-binary", kiro]
        guarded = "DefenseClaw · Kiro"

    def verify():
        return runner.invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)

    def healthy():
        status = json.loads(runner.invoke(acp_cmd, ["status", "--json"], obj=app).output)
        return status["bindings"]["zed/kiro"]["healthy"]

    try:
        result = runner.invoke(acp_cmd, args, obj=app)
        assert result.exit_code == 0, result.output
        document = json.loads(settings.read_text())
        original = document["agent_servers"][guarded]

        def copy_with(env=None, gateway=None):
            entry = json.loads(json.dumps(original))
            if env is not None:
                entry["env"] = env
            if gateway is not None:
                entry["args"][entry["args"].index("--gateway") + 1] = gateway
            return entry

        evil = str(tmp_path / "evil.so")
        variants = {
            "env": copy_with(env={"LD_PRELOAD": evil}),
            "gateway": copy_with(gateway="http://127.0.0.1:1/evil"),
            "env and gateway": copy_with(env={"LD_PRELOAD": evil}, gateway="http://127.0.0.1:1/evil"),
        }
        for label, entry in variants.items():
            tampered = json.loads(json.dumps(document))
            tampered["agent_servers"]["Kiro 2"] = entry
            settings.write_text(json.dumps(tampered))
            result = verify()
            assert result.exit_code != 0 and "Kiro 2" in result.output, (label, result.output)
            assert not healthy(), label

        # Control: an exact copy has no launch field of its own; it launches
        # what the pinned entry launches and still verifies.
        same = json.loads(json.dumps(document))
        same["agent_servers"]["Kiro 2"] = copy_with()
        settings.write_text(json.dumps(same))
        assert verify().exit_code == 0, verify().output

        # A clean copy cannot borrow a gateway from a pinned entry that drifted.
        drifted = json.loads(json.dumps(document))
        drifted["agent_servers"][guarded] = copy_with(gateway="http://127.0.0.1:1/evil")
        drifted["agent_servers"]["Kiro 2"] = copy_with(gateway="http://127.0.0.1:1/evil")
        settings.write_text(json.dumps(drifted))
        result = verify()
        assert result.exit_code != 0 and "Kiro 2" in result.output, result.output

        settings.write_text(json.dumps(document))
        assert verify().exit_code == 0, verify().output
    finally:
        cleanup_app(app, db_path, data_dir)


@pytest.mark.parametrize("entry_names", [[], ["My Kiro"]], ids=["reserved", "adopted"])
def test_repair_setup_drops_an_env_its_pin_does_not_prove(tmp_path, monkeypatch, entry_names):
    """Plain setup keeps only the env the binding's pin sealed; explicit adoption keeps the operator's."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    kiro = _binary(tmp_path / "kiro-cli")
    runner = CliRunner()
    setup = ["setup", "--client", "zed", "--agent", "kiro", "--activate",
             "--guard-binary", guard, "--agent-binary", kiro]
    if entry_names:
        sealed = {"KIRO_LOG": "1"}
        settings.write_text(json.dumps({"agent_servers": {
            "My Kiro": {"command": kiro, "args": ["acp"], "env": sealed},
        }}))
        first = ["adopt", "--client", "zed", "--guard-binary", guard, "--activate", "--yes"]
        guarded = "My Kiro"
    else:
        sealed = {}
        first = setup
        guarded = "DefenseClaw · Kiro"

    def verify():
        return runner.invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)

    def env():
        return json.loads(settings.read_text())["agent_servers"][guarded]["env"]

    try:
        result = runner.invoke(acp_cmd, first, obj=app)
        assert result.exit_code == 0, result.output
        assert env() == sealed
        # A healthy repeat setup keeps the env the pin proves (the adopted one).
        result = runner.invoke(acp_cmd, setup, obj=app)
        assert result.exit_code == 0, result.output
        assert env() == sealed and verify().exit_code == 0

        document = json.loads(settings.read_text())
        document["agent_servers"][guarded]["env"] = {**sealed, "LD_PRELOAD": str(tmp_path / "evil.so")}
        settings.write_text(json.dumps(document))
        drifted = verify()
        assert drifted.exit_code != 0 and "client configuration digest has drifted" in drifted.output
        result = runner.invoke(acp_cmd, [*_repair_args(drifted.output), "--json-output"], obj=app)
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["client"] == "zed"
        assert "Reset the env of editor entry" in result.stderr
        assert env() == {}
        assert verify().exit_code == 0, verify().output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_legacy_adopted_entry_keeps_its_env_through_the_upgrade_setup(tmp_path, monkeypatch):
    """A 1.0.3 adoption (whole-file pin, no adopted_entries) keeps the env that file pin proves."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    kiro = _binary(tmp_path / "kiro-cli")
    lock = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
    settings.write_text(json.dumps({"agent_servers": {
        "My Kiro": {"command": kiro, "args": ["acp"], "env": {"KIRO_LOG": "1"}},
    }}))
    runner = CliRunner()

    def verify():
        return runner.invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)

    try:
        result = runner.invoke(
            acp_cmd, ["adopt", "--client", "zed", "--guard-binary", guard, "--activate", "--yes"], obj=app,
        )
        assert result.exit_code == 0, result.output
        document = json.loads(lock.read_text())
        del document["client"]["adopted_entries"]
        document["client"]["config_sha256"] = cmd_acp_module._sha256_file(str(settings))
        cmd_acp_module.atomic_write_private_bytes(lock, json.dumps(document).encode())
        assert verify().exit_code == 0, verify().output

        # The setup that moves a legacy pin to entry pins (see the docs).
        result = runner.invoke(acp_cmd, [
            "setup", "--client", "zed", "--agent", "kiro", "--activate",
            "--guard-binary", guard, "--agent-binary", kiro,
        ], obj=app)
        assert result.exit_code == 0, result.output
        servers = json.loads(settings.read_text())["agent_servers"]
        assert list(servers) == ["My Kiro"] and servers["My Kiro"]["env"] == {"KIRO_LOG": "1"}
        pin = json.loads(lock.read_text())["client"]
        assert pin["config_sha256"].startswith(cmd_acp_module._ENTRY_DIGEST_PREFIX)
        assert pin["adopted_entries"] == ["My Kiro"]
        assert verify().exit_code == 0, verify().output
    finally:
        cleanup_app(app, db_path, data_dir)
