"""Until 1.1, older config files naming removed connectors still load."""

import pytest
from defenseclaw import config


@pytest.mark.parametrize("version", (8, 9))
def test_retired_connector_roster_loads_with_remaining_peer(tmp_path, caplog, version):
    (tmp_path / "config.yaml").write_text(
        f"config_version: {version}\n"
        "guardrail:\n"
        "  connector: openhands\n"
        "  connectors:\n"
        "    openhands: {}\n"
        "    codex: {}\n"
        "claw:\n"
        "  mode: omnigent\n",
        encoding="utf-8",
    )

    loaded = config.load(data_dir=tmp_path)

    assert loaded.active_connectors() == ["codex"]
    assert loaded.guardrail.connector == "codex"
    assert loaded.claw.mode == ""
    assert "until 1.1" in caplog.text
    loaded.save()
    persisted = (tmp_path / "config.yaml").read_text(encoding="utf-8").lower()
    assert "openhands" not in persisted
    assert "omnigent" not in persisted


def test_retired_connector_nested_policy_keys_are_dropped():
    raw = {
        "asset_policy": {"connectors": {"Open_Hands": {"mode": "action"}, "codex": {}}},
        "application_protection": {"include_connectors": ["omnigent", "codex"]},
        "guardrail": {"profiles": {"workers": {"connectors": {"openhands": {}, "codex": {}}}}},
    }

    config._drop_retired_connector_settings(raw)

    assert raw["asset_policy"]["connectors"] == {"codex": {}}
    assert raw["application_protection"]["include_connectors"] == ["codex"]
    assert raw["guardrail"]["profiles"]["workers"]["connectors"] == {"codex": {}}


def test_retired_connector_only_roster_loads_as_unconfigured(tmp_path):
    (tmp_path / "config.yaml").write_text(
        "config_version: 8\n"
        "guardrail:\n  connector: openhands\n  connectors:\n    openhands: {}\n"
        "claw:\n  mode: omnigent\n",
        encoding="utf-8",
    )

    loaded = config.load(data_dir=tmp_path)

    assert loaded.active_connectors() == []
    assert not loaded.has_connector_configured()


def test_retired_connector_only_allow_lists_stay_restrictive():
    raw = {
        "application_protection": {"enabled": True, "include_connectors": ["openhands"]},
        "openshell": {
            "enabled": True,
            "harnesses": ["omnigent"],
            "admin": {"allowed_harnesses": ["openhands"]},
        },
        "guardrail": {
            "profiles": {"workers": {"sandbox": {"allowed_harnesses": ["omnigent"]}}},
            "profile_assignments": [{"profile": "workers", "match": {"connectors": ["openhands"]}}],
        },
    }

    config._drop_retired_connector_settings(raw)

    assert raw["application_protection"]["enabled"] is False
    assert raw["openshell"]["enabled"] is False
    assert raw["openshell"]["admin"]["allowed"] is False
    assert raw["guardrail"]["profiles"]["workers"]["sandbox"]["allowed"] is False
    assert raw["guardrail"]["profile_assignments"] == []
