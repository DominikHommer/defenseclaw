# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from click.testing import CliRunner
from defenseclaw.commands import cmd_config
from defenseclaw.context import AppContext

from tests.environment import isolated_home_env


def test_listener_change_audits_to_the_listener_that_is_still_running(tmp_path, monkeypatch):
    for key, value in isolated_home_env(tmp_path / "home").items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    path = tmp_path / "config.yaml"
    path.write_text(
        f"config_version: 9\ndata_dir: {tmp_path.as_posix()}\ngateway:\n  api_port: 19080\nobservability: {{}}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(cmd_config.config_module, "config_path", lambda: path)
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(path))
    monkeypatch.setenv("DEFENSECLAW_GATEWAY_TOKEN", "provided by the test fixture")
    monkeypatch.setattr("defenseclaw.gateway.local_policy_digest", lambda *a, **kw: None)
    monkeypatch.setattr(cmd_config, "_refresh_stopped_gateway_hooks", lambda *a: [])
    calls = []

    class Client:
        def __init__(self, **kwargs):
            calls.append(kwargs)

        def emit_cli_observability(self, payload):
            assert payload["activity"]["actor"]
            assert payload["activity"]["diff"][0]["path"] == "gateway.api_port"

        def close(self):
            pass

    monkeypatch.setattr("defenseclaw.logger.OrchestratorClient", Client)
    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "gateway.api_port", "19081"], obj=AppContext())
    assert result.exit_code == 0, result.output
    assert len(calls) == 1 and calls[0]["port"] == 19080, calls
    assert "19081" in path.read_text(encoding="utf-8")
